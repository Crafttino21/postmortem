#include "core/cper/guid.hpp"

#include <cctype>

namespace postmortem::cper {
namespace {

std::uint16_t read_u16(std::span<const std::uint8_t> bytes, std::size_t offset) {
    return static_cast<std::uint16_t>(bytes[offset] | (bytes[offset + 1] << 8));
}

std::uint32_t read_u32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

void append_hex(std::string& out, std::uint64_t value, int digits) {
    static constexpr char kDigits[] = "0123456789abcdef";
    for (int shift = (digits - 1) * 4; shift >= 0; shift -= 4) {
        out += kDigits[(value >> shift) & 0xF];
    }
}

std::optional<unsigned> hex_value(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A' + 10);
    return std::nullopt;
}

// Parses `digits` hex characters starting at `pos`, advancing it.
std::optional<std::uint64_t> take_hex(std::string_view text, std::size_t& pos, int digits) {
    std::uint64_t value = 0;
    for (int i = 0; i < digits; ++i) {
        if (pos >= text.size()) return std::nullopt;
        const auto nibble = hex_value(text[pos]);
        if (!nibble.has_value()) return std::nullopt;
        value = (value << 4) | *nibble;
        ++pos;
    }
    return value;
}

bool take_dash(std::string_view text, std::size_t& pos) {
    if (pos >= text.size() || text[pos] != '-') return false;
    ++pos;
    return true;
}

Guid make(std::uint32_t d1, std::uint16_t d2, std::uint16_t d3, std::uint8_t b0, std::uint8_t b1,
          std::uint8_t b2, std::uint8_t b3, std::uint8_t b4, std::uint8_t b5, std::uint8_t b6,
          std::uint8_t b7) {
    return Guid{d1, d2, d3, {b0, b1, b2, b3, b4, b5, b6, b7}};
}

}  // namespace

namespace guids {

const Guid kProcessorGeneric =
    make(0x9876ccad, 0x47b4, 0x4bdb, 0xb6, 0x5e, 0x16, 0xf1, 0x93, 0xc4, 0xf3, 0xdb);
const Guid kIa32X64Processor =
    make(0xdc3ea0b0, 0xa144, 0x4797, 0xb9, 0x5b, 0x53, 0xfa, 0x24, 0x2b, 0x6e, 0x1d);
const Guid kPlatformMemory =
    make(0xa5bc1114, 0x6f64, 0x4ede, 0xb8, 0x63, 0x3e, 0x83, 0xed, 0x7c, 0x83, 0xb1);

const Guid kCacheCheck =
    make(0xa55701f5, 0xe3ef, 0x43de, 0xac, 0x72, 0x24, 0x9b, 0x57, 0x3f, 0xad, 0x2c);
const Guid kTlbCheck =
    make(0xfc06b535, 0x5e1f, 0x4562, 0x9f, 0x25, 0x0a, 0x3b, 0x9a, 0xdb, 0x63, 0xc3);
const Guid kBusCheck =
    make(0x1cf3f8b3, 0xc5b1, 0x49a2, 0xaa, 0x59, 0x5e, 0xef, 0x92, 0xff, 0xa6, 0x3c);
const Guid kMicroArchitecturalCheck =
    make(0x48ab7f57, 0xdc34, 0x4f6c, 0xa7, 0xd3, 0xb0, 0xb5, 0xb0, 0xa7, 0x43, 0x14);

}  // namespace guids

std::optional<Guid> read_guid(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 16) return std::nullopt;

    Guid guid;
    guid.data1 = read_u32(bytes, 0);
    guid.data2 = read_u16(bytes, 4);
    guid.data3 = read_u16(bytes, 6);
    for (std::size_t i = 0; i < 8; ++i) guid.data4[i] = bytes[8 + i];
    return guid;
}

std::string to_string(const Guid& guid) {
    std::string out;
    out.reserve(36);
    append_hex(out, guid.data1, 8);
    out += '-';
    append_hex(out, guid.data2, 4);
    out += '-';
    append_hex(out, guid.data3, 4);
    out += '-';
    append_hex(out, guid.data4[0], 2);
    append_hex(out, guid.data4[1], 2);
    out += '-';
    for (std::size_t i = 2; i < 8; ++i) append_hex(out, guid.data4[i], 2);
    return out;
}

std::optional<Guid> parse_guid(std::string_view text) {
    if (!text.empty() && text.front() == '{' && text.back() == '}') {
        text = text.substr(1, text.size() - 2);
    }

    std::size_t pos = 0;
    const auto d1 = take_hex(text, pos, 8);
    if (!d1.has_value() || !take_dash(text, pos)) return std::nullopt;
    const auto d2 = take_hex(text, pos, 4);
    if (!d2.has_value() || !take_dash(text, pos)) return std::nullopt;
    const auto d3 = take_hex(text, pos, 4);
    if (!d3.has_value() || !take_dash(text, pos)) return std::nullopt;

    Guid guid;
    guid.data1 = static_cast<std::uint32_t>(*d1);
    guid.data2 = static_cast<std::uint16_t>(*d2);
    guid.data3 = static_cast<std::uint16_t>(*d3);

    for (std::size_t i = 0; i < 8; ++i) {
        if (i == 2 && !take_dash(text, pos)) return std::nullopt;
        const auto byte = take_hex(text, pos, 2);
        if (!byte.has_value()) return std::nullopt;
        guid.data4[i] = static_cast<std::uint8_t>(*byte);
    }

    if (pos != text.size()) return std::nullopt;   // trailing junk
    return guid;
}

bool is_null(const Guid& guid) {
    return guid == Guid{};
}

std::string_view known_name(const Guid& guid) {
    if (guid == guids::kProcessorGeneric) return "Processor Generic";
    if (guid == guids::kIa32X64Processor) return "IA32/X64 Processor Error";
    if (guid == guids::kPlatformMemory) return "Platform Memory Error";
    if (guid == guids::kCacheCheck) return "Cache Check";
    if (guid == guids::kTlbCheck) return "TLB Check";
    if (guid == guids::kBusCheck) return "Bus Check";
    if (guid == guids::kMicroArchitecturalCheck) return "Micro-Architectural Check";
    return {};
}

}  // namespace postmortem::cper
