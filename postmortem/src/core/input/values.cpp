#include "core/input/values.hpp"

#include <array>
#include <cctype>
#include <limits>

namespace postmortem::input {
namespace {

bool is_space(char c) {
    return std::isspace(static_cast<unsigned char>(c)) != 0;
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Strips everything people put between hex bytes: whitespace, commas, colons
// and the 0x prefixes of a pasted C array.
std::string compact_hex(std::string_view text) {
    std::string out;
    out.reserve(text.size());

    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (is_space(c) || c == ',' || c == ':' || c == ';' || c == '_') continue;
        if ((c == '0') && i + 1 < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
            ++i;   // skip the "0x"
            continue;
        }
        out += c;
    }
    return out;
}

std::vector<std::uint8_t> hex_to_bytes(std::string_view compact) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(compact.size() / 2);
    for (std::size_t i = 0; i + 1 < compact.size(); i += 2) {
        const int high = hex_value(compact[i]);
        const int low = hex_value(compact[i + 1]);
        bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return bytes;
}

bool all_hex_digits(std::string_view text) {
    if (text.empty()) return false;
    for (const char c : text) {
        if (hex_value(c) < 0) return false;
    }
    return true;
}

int base64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// Standard base64 with '=' padding. Returns false on any character outside the
// alphabet, so a hex string never decodes here by accident.
bool base64_to_bytes(std::string_view text, std::vector<std::uint8_t>& out) {
    std::string compact;
    compact.reserve(text.size());
    for (const char c : text) {
        if (!is_space(c)) compact += c;
    }
    if (compact.empty() || compact.size() % 4 != 0) return false;

    std::size_t padding = 0;
    while (padding < 2 && !compact.empty() && compact.back() == '=') {
        compact.pop_back();
        ++padding;
    }

    std::uint32_t accumulator = 0;
    int bits = 0;
    for (const char c : compact) {
        const int value = base64_value(c);
        if (value < 0) return false;
        accumulator = (accumulator << 6) | static_cast<std::uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((accumulator >> bits) & 0xFF));
        }
    }
    return true;
}

bool starts_with_cper(const std::vector<std::uint8_t>& bytes) {
    return bytes.size() >= 4 && bytes[0] == 'C' && bytes[1] == 'P' && bytes[2] == 'E' &&
           bytes[3] == 'R';
}

}  // namespace

BlobResult parse_blob(std::string_view text) {
    BlobResult result;

    bool has_content = false;
    for (const char c : text) {
        if (!is_space(c)) has_content = true;
    }
    if (!has_content) {
        result.error = "the value is empty";
        return result;
    }

    const std::string compact = compact_hex(text);
    const bool hex_possible = all_hex_digits(compact) && compact.size() % 2 == 0;

    std::vector<std::uint8_t> hex_bytes;
    if (hex_possible) hex_bytes = hex_to_bytes(compact);

    std::vector<std::uint8_t> base64_bytes;
    const bool base64_possible = base64_to_bytes(text, base64_bytes);

    // A string of an even number of hex digits can also be valid base64, and
    // the two decode to completely different bytes. The record's own "CPER"
    // signature settles it whenever exactly one reading produces it; otherwise
    // hex wins, because that is the form spec §5 documents.
    const bool hex_is_cper = hex_possible && starts_with_cper(hex_bytes);
    const bool base64_is_cper = base64_possible && starts_with_cper(base64_bytes);

    if (base64_is_cper && !hex_is_cper) {
        result.ok = true;
        result.bytes = std::move(base64_bytes);
        result.format = "base64";
        return result;
    }
    if (hex_possible) {
        result.ok = true;
        result.bytes = std::move(hex_bytes);
        result.format = "hex";
        return result;
    }
    if (base64_possible) {
        result.ok = true;
        result.bytes = std::move(base64_bytes);
        result.format = "base64";
        return result;
    }

    if (all_hex_digits(compact) && compact.size() % 2 != 0) {
        result.error = "the value looks like hex but has an odd number of digits (" +
                       std::to_string(compact.size()) + "); a byte needs two";
        return result;
    }
    result.error = "the value is neither hex nor base64";
    return result;
}

IntegerResult parse_u64(std::string_view text) {
    IntegerResult result;

    std::string compact;
    for (const char c : text) {
        if (!is_space(c) && c != '_' && c != '\'') compact += c;
    }
    if (compact.empty()) {
        result.error = "the value is empty";
        return result;
    }

    int base = 0;
    std::string_view digits = compact;
    if (compact.size() > 2 && compact[0] == '0' && (compact[1] == 'x' || compact[1] == 'X')) {
        base = 16;
        digits = std::string_view(compact).substr(2);
    } else if (compact.size() > 2 && compact[0] == '0' &&
               (compact[1] == 'b' || compact[1] == 'B')) {
        base = 2;
        digits = std::string_view(compact).substr(2);
    } else {
        // No prefix: decimal if it could be, hex if it could only be hex.
        bool decimal_only = true;
        for (const char c : compact) {
            if (c < '0' || c > '9') decimal_only = false;
        }
        base = decimal_only ? 10 : 16;
        // "0b1" with base 2 already handled; a bare "b" here is a hex digit.
    }

    if (digits.empty()) {
        result.error = "the value has a base prefix but no digits";
        return result;
    }

    std::uint64_t value = 0;
    for (const char c : digits) {
        int digit = hex_value(c);
        if (digit < 0 || digit >= base) {
            result.error = std::string("'") + c + "' is not a valid digit in base " +
                           std::to_string(base);
            return result;
        }
        // Reject anything that would not fit in 64 bits rather than wrapping
        // silently into a different register value.
        const std::uint64_t limit = (~0ull - static_cast<std::uint64_t>(digit)) /
                                    static_cast<std::uint64_t>(base);
        if (value > limit) {
            result.error = "the value does not fit in 64 bits";
            return result;
        }
        value = value * static_cast<std::uint64_t>(base) + static_cast<std::uint64_t>(digit);
    }

    result.ok = true;
    result.value = value;
    result.base = base;
    return result;
}

DurationResult parse_duration(std::string_view text) {
    DurationResult result;

    std::string compact;
    for (const char c : text) {
        if (!is_space(c)) compact += c;
    }
    if (compact.empty()) {
        result.error = "the duration is empty";
        return result;
    }

    char unit = 'd';   // a bare number means days, matching "--since 90d"
    if (const char last = compact.back(); last < '0' || last > '9') {
        unit = static_cast<char>(std::tolower(static_cast<unsigned char>(last)));
        compact.pop_back();
    }
    if (compact.empty()) {
        result.error = "the duration has a unit but no number";
        return result;
    }

    std::int64_t multiplier = 0;
    switch (unit) {
        case 's': multiplier = 1; break;
        case 'm': multiplier = 60; break;
        case 'h': multiplier = 3600; break;
        case 'd': multiplier = 86400; break;
        case 'w': multiplier = 7 * 86400; break;
        case 'y': multiplier = 365 * 86400; break;
        default:
            result.error = std::string("unknown duration unit '") + unit +
                           "'; use s, m, h, d, w or y";
            return result;
    }

    std::int64_t value = 0;
    for (const char c : compact) {
        if (c < '0' || c > '9') {
            result.error = std::string("'") + c + "' is not a digit";
            return result;
        }
        // Cap rather than overflow: a nonsensical span is clamped to one that
        // still means "everything in the log".
        if (value > (std::numeric_limits<std::int64_t>::max() / 10 - 9) / multiplier) {
            result.error = "the duration is too large";
            return result;
        }
        value = value * 10 + (c - '0');
    }

    result.ok = true;
    result.seconds = value * multiplier;
    return result;
}

}  // namespace postmortem::input
