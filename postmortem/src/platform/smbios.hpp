// SMBIOS/DMI access via GetSystemFirmwareTable(RSMB) (spec §4.8).
//
// The table is firmware-supplied data of exactly the kind CLAUDE.md demands
// bounds-checking for: every length and string index comes from the BIOS, and
// broken tables are common on consumer boards. parse_structures() therefore
// validates each record against the buffer end and stops cleanly on the first
// inconsistency instead of reading past it.
//
// Field offsets below cite DSP0134 (SMBIOS Reference Specification) 3.7.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace postmortem::platform {

struct SmbiosTable {
    std::uint8_t major = 0;
    std::uint8_t minor = 0;
    std::vector<std::uint8_t> data;   // the packed structure stream
};

// One SMBIOS structure. `formatted` covers the header plus the fixed-length
// area and points into the SmbiosTable it was parsed from, so it must not
// outlive that table.
struct SmbiosStructure {
    std::uint8_t type = 0;
    std::uint16_t handle = 0;
    std::span<const std::uint8_t> formatted;
    std::vector<std::string> strings;

    // Reads the byte at `offset` from the start of the structure, or nullopt
    // if this structure's formatted area is too short to contain it - which is
    // how SMBIOS signals "field added in a later version, absent here".
    [[nodiscard]] std::optional<std::uint8_t> byte_at(std::size_t offset) const;

    // Resolves a string-number field. SMBIOS string indices are 1-based and 0
    // means "no string".
    [[nodiscard]] std::string string_field(std::size_t offset) const;
};

[[nodiscard]] std::optional<SmbiosTable> read_smbios_table();
[[nodiscard]] std::vector<SmbiosStructure> parse_structures(const SmbiosTable& table);

struct FirmwareInfo {
    bool available = false;
    std::uint8_t smbios_major = 0;
    std::uint8_t smbios_minor = 0;

    // Type 0 - BIOS Information (DSP0134 §7.1)
    std::string bios_vendor;
    std::string bios_version;
    std::string bios_release_date;
    std::optional<unsigned> bios_major_release;
    std::optional<unsigned> bios_minor_release;

    // Type 1 - System Information (§7.2)
    std::string system_manufacturer;
    std::string system_product;
    std::string system_version;

    // Type 2 - Baseboard (§7.3). The board model is what BIOS-setting advice
    // in spec §4.9 has to be phrased against.
    std::string board_manufacturer;
    std::string board_product;
    std::string board_version;
};

[[nodiscard]] FirmwareInfo query_firmware_info();

}  // namespace postmortem::platform
