#include "platform/smbios.hpp"

#include <windows.h>

#include <cstring>

#include "platform/strings.hpp"

namespace postmortem::platform {
namespace {

// 'RSMB', spelled out rather than written as a multi-character literal so the
// byte order is explicit and clang-cl does not warn about it.
constexpr DWORD kRawSmbiosProvider = 0x52534D42u;

// Header Windows prepends to the raw table (documented with
// GetSystemFirmwareTable).
#pragma pack(push, 1)
struct RawSmbiosData {
    BYTE  used_20_calling_method;
    BYTE  smbios_major_version;
    BYTE  smbios_minor_version;
    BYTE  dmi_revision;
    DWORD length;
    // BYTE table[length] follows
};
#pragma pack(pop)

constexpr std::uint8_t kTypeBios = 0;
constexpr std::uint8_t kTypeSystem = 1;
constexpr std::uint8_t kTypeBaseboard = 2;
constexpr std::uint8_t kTypeEndOfTable = 127;

constexpr std::size_t kHeaderSize = 4;  // type, length, handle[2]

std::string clean(std::string_view value) {
    std::string trimmed = trim(value);
    return is_firmware_placeholder(trimmed) ? std::string{} : trimmed;
}

}  // namespace

std::optional<std::uint8_t> SmbiosStructure::byte_at(std::size_t offset) const {
    if (offset >= formatted.size()) return std::nullopt;
    return formatted[offset];
}

std::string SmbiosStructure::string_field(std::size_t offset) const {
    const auto index = byte_at(offset);
    if (!index.has_value() || *index == 0) return {};
    if (*index > strings.size()) return {};   // dangling index: broken table
    return strings[*index - 1];
}

std::optional<SmbiosTable> read_smbios_table() {
    const UINT size = ::GetSystemFirmwareTable(kRawSmbiosProvider, 0, nullptr, 0);
    if (size < sizeof(RawSmbiosData)) return std::nullopt;

    std::vector<std::uint8_t> buffer(size);
    const UINT written = ::GetSystemFirmwareTable(kRawSmbiosProvider, 0, buffer.data(), size);
    if (written == 0 || written > size || written < sizeof(RawSmbiosData)) return std::nullopt;
    buffer.resize(written);

    RawSmbiosData header{};
    std::memcpy(&header, buffer.data(), sizeof(header));

    const std::size_t available = buffer.size() - sizeof(RawSmbiosData);
    // Trust the smaller of the declared length and what was actually written.
    const std::size_t length =
        header.length <= available ? static_cast<std::size_t>(header.length) : available;

    SmbiosTable table;
    table.major = header.smbios_major_version;
    table.minor = header.smbios_minor_version;
    table.data.assign(buffer.begin() + sizeof(RawSmbiosData),
                      buffer.begin() + sizeof(RawSmbiosData) + length);
    return table;
}

std::vector<SmbiosStructure> parse_structures(const SmbiosTable& table) {
    std::vector<SmbiosStructure> structures;
    const std::vector<std::uint8_t>& data = table.data;

    std::size_t offset = 0;
    while (offset + kHeaderSize <= data.size()) {
        const std::uint8_t type = data[offset];
        const std::uint8_t length = data[offset + 1];

        // A formatted area shorter than the header, or one that runs past the
        // buffer, means the table is corrupt. Stop rather than resynchronise:
        // anything after this point is untrustworthy.
        if (length < kHeaderSize) break;
        if (offset + length > data.size()) break;

        SmbiosStructure structure;
        structure.type = type;
        std::uint16_t handle = 0;
        std::memcpy(&handle, data.data() + offset + 2, sizeof(handle));
        structure.handle = handle;
        structure.formatted = std::span<const std::uint8_t>(data.data() + offset, length);

        // The unformatted section is a run of NUL-terminated strings closed by
        // an empty one; a structure with no strings is just the double NUL.
        std::size_t pos = offset + length;
        if (pos + 1 < data.size() && data[pos] == 0 && data[pos + 1] == 0) {
            pos += 2;
        } else {
            bool terminated = false;
            while (pos < data.size()) {
                const std::size_t start = pos;
                while (pos < data.size() && data[pos] != 0) ++pos;
                if (pos >= data.size()) break;   // unterminated string: corrupt

                structure.strings.emplace_back(reinterpret_cast<const char*>(data.data() + start),
                                               pos - start);
                ++pos;   // step over the NUL
                if (pos < data.size() && data[pos] == 0) {
                    ++pos;
                    terminated = true;
                    break;
                }
            }
            if (!terminated) {
                structures.push_back(std::move(structure));
                break;
            }
        }

        const bool end_of_table = structure.type == kTypeEndOfTable;
        structures.push_back(std::move(structure));
        if (end_of_table) break;

        offset = pos;
    }

    return structures;
}

FirmwareInfo query_firmware_info() {
    FirmwareInfo info;

    const auto table = read_smbios_table();
    if (!table.has_value()) return info;

    info.available = true;
    info.smbios_major = table->major;
    info.smbios_minor = table->minor;

    for (const SmbiosStructure& structure : parse_structures(*table)) {
        switch (structure.type) {
            case kTypeBios:
                info.bios_vendor = clean(structure.string_field(0x04));
                info.bios_version = clean(structure.string_field(0x05));
                info.bios_release_date = clean(structure.string_field(0x08));
                // Offsets 14h/15h were added in SMBIOS 2.4; byte_at() returns
                // nullopt on older tables that stop short of them.
                if (const auto major = structure.byte_at(0x14)) {
                    if (*major != 0xFF) info.bios_major_release = *major;
                }
                if (const auto minor = structure.byte_at(0x15)) {
                    if (*minor != 0xFF) info.bios_minor_release = *minor;
                }
                break;
            case kTypeSystem:
                info.system_manufacturer = clean(structure.string_field(0x04));
                info.system_product = clean(structure.string_field(0x05));
                info.system_version = clean(structure.string_field(0x06));
                break;
            case kTypeBaseboard:
                info.board_manufacturer = clean(structure.string_field(0x04));
                info.board_product = clean(structure.string_field(0x05));
                info.board_version = clean(structure.string_field(0x06));
                break;
            default:
                break;
        }
    }

    return info;
}

}  // namespace postmortem::platform
