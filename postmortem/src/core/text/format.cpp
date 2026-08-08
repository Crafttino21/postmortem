#include "core/text/format.hpp"

#include <algorithm>
#include <array>

namespace postmortem::text {
namespace {

constexpr std::array<char, 16> kHexDigits{
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

}  // namespace

std::string to_hex(std::uint64_t value, int digits) {
    std::string reversed;
    do {
        reversed += kHexDigits[value & 0xF];
        value >>= 4;
    } while (value != 0);

    while (static_cast<int>(reversed.size()) < digits) reversed += '0';

    std::string out = "0x";
    out.append(reversed.rbegin(), reversed.rend());
    return out;
}

std::string hex_dump(std::span<const std::uint8_t> bytes, std::size_t base_offset,
                     std::size_t indent) {
    constexpr std::size_t kPerLine = 16;

    std::string out;
    for (std::size_t line = 0; line < bytes.size(); line += kPerLine) {
        const std::size_t count = std::min(kPerLine, bytes.size() - line);

        out.append(indent, ' ');
        // Offsets are 8 hex digits so that columns stay aligned for records
        // larger than 64 KiB.
        const std::string offset = to_hex(base_offset + line, 8);
        out.append(offset.begin() + 2, offset.end());   // drop the "0x"
        out += "  ";

        for (std::size_t i = 0; i < kPerLine; ++i) {
            if (i < count) {
                out += kHexDigits[(bytes[line + i] >> 4) & 0xF];
                out += kHexDigits[bytes[line + i] & 0xF];
            } else {
                out += "  ";
            }
            out += ' ';
            if (i == 7) out += ' ';   // gap between the two halves
        }

        out += ' ';
        for (std::size_t i = 0; i < count; ++i) {
            const std::uint8_t byte = bytes[line + i];
            out += (byte >= 0x20 && byte < 0x7F) ? static_cast<char>(byte) : '.';
        }
        out += '\n';
    }
    return out;
}

// --- Time ------------------------------------------------------------------

namespace {

// Howard Hinnant's days_from_civil: exact for the whole proleptic Gregorian
// calendar and free of the C library's timezone and locale behaviour.
std::int64_t days_from_civil(std::int64_t year, unsigned month, unsigned day) {
    year -= month <= 2 ? 1 : 0;
    const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
    const auto year_of_era = static_cast<unsigned>(year - era * 400);
    const unsigned day_of_year =
        (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    const unsigned day_of_era =
        year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    return era * 146097 + static_cast<std::int64_t>(day_of_era) - 719468;
}

void civil_from_days(std::int64_t days, std::int64_t& year, unsigned& month, unsigned& day) {
    days += 719468;
    const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const auto day_of_era = static_cast<std::uint64_t>(days - era * 146097);
    const std::uint64_t year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    const std::int64_t y = static_cast<std::int64_t>(year_of_era) + era * 400;
    const std::uint64_t day_of_year =
        day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    const std::uint64_t mp = (5 * day_of_year + 2) / 153;
    day = static_cast<unsigned>(day_of_year - (153 * mp + 2) / 5 + 1);
    month = static_cast<unsigned>(mp + (mp < 10 ? 3 : -9));
    year = y + (month <= 2 ? 1 : 0);
}

bool take_digits(std::string_view text, std::size_t& pos, int count, unsigned& out) {
    unsigned value = 0;
    for (int i = 0; i < count; ++i) {
        if (pos >= text.size() || text[pos] < '0' || text[pos] > '9') return false;
        value = value * 10 + static_cast<unsigned>(text[pos] - '0');
        ++pos;
    }
    out = value;
    return true;
}

std::string pad(std::int64_t value, int width) {
    std::string text = std::to_string(value);
    while (static_cast<int>(text.size()) < width) text.insert(text.begin(), '0');
    return text;
}

}  // namespace

std::optional<Instant> parse_iso8601(std::string_view text) {
    std::size_t pos = 0;
    unsigned year = 0;
    unsigned month = 0;
    unsigned day = 0;
    unsigned hour = 0;
    unsigned minute = 0;
    unsigned second = 0;

    if (!take_digits(text, pos, 4, year)) return std::nullopt;
    if (pos >= text.size() || text[pos++] != '-') return std::nullopt;
    if (!take_digits(text, pos, 2, month)) return std::nullopt;
    if (pos >= text.size() || text[pos++] != '-') return std::nullopt;
    if (!take_digits(text, pos, 2, day)) return std::nullopt;
    if (pos >= text.size() || (text[pos] != 'T' && text[pos] != ' ')) return std::nullopt;
    ++pos;
    if (!take_digits(text, pos, 2, hour)) return std::nullopt;
    if (pos >= text.size() || text[pos++] != ':') return std::nullopt;
    if (!take_digits(text, pos, 2, minute)) return std::nullopt;
    if (pos >= text.size() || text[pos++] != ':') return std::nullopt;
    if (!take_digits(text, pos, 2, second)) return std::nullopt;

    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 ||
        second > 60) {
        return std::nullopt;
    }

    // Windows writes seven fractional digits; accept any number of them.
    unsigned nanoseconds = 0;
    if (pos < text.size() && text[pos] == '.') {
        ++pos;
        unsigned scale = 100000000u;
        while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
            nanoseconds += static_cast<unsigned>(text[pos] - '0') * scale;
            scale /= 10;
            ++pos;
            if (scale == 0) {
                while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') ++pos;
                break;
            }
        }
    }

    std::int64_t offset_seconds = 0;
    if (pos < text.size() && (text[pos] == '+' || text[pos] == '-')) {
        const int sign = text[pos] == '-' ? -1 : 1;
        ++pos;
        unsigned offset_hour = 0;
        unsigned offset_minute = 0;
        if (!take_digits(text, pos, 2, offset_hour)) return std::nullopt;
        if (pos < text.size() && text[pos] == ':') ++pos;
        if (!take_digits(text, pos, 2, offset_minute)) return std::nullopt;
        offset_seconds = sign * (offset_hour * 3600LL + offset_minute * 60LL);
    }

    Instant instant;
    instant.seconds = days_from_civil(year, month, day) * 86400LL + hour * 3600LL +
                      minute * 60LL + second - offset_seconds;
    instant.nanoseconds = nanoseconds;
    return instant;
}

std::string format_utc(std::int64_t unix_seconds) {
    std::int64_t days = unix_seconds / 86400;
    std::int64_t rest = unix_seconds % 86400;
    if (rest < 0) {
        rest += 86400;
        --days;
    }

    std::int64_t year = 0;
    unsigned month = 0;
    unsigned day = 0;
    civil_from_days(days, year, month, day);

    return pad(year, 4) + "-" + pad(month, 2) + "-" + pad(day, 2) + " " +
           pad(rest / 3600, 2) + ":" + pad((rest / 60) % 60, 2) + ":" + pad(rest % 60, 2) + "Z";
}

std::string format_span(std::int64_t seconds) {
    const bool negative = seconds < 0;
    std::int64_t value = negative ? -seconds : seconds;

    std::string out;
    if (value < 60) {
        out = std::to_string(value) + "s";
    } else {
        const std::int64_t days = value / 86400;
        const std::int64_t hours = (value / 3600) % 24;
        const std::int64_t minutes = (value / 60) % 60;
        if (days > 0) out += std::to_string(days) + "d ";
        if (days > 0 || hours > 0) out += std::to_string(hours) + "h ";
        out += std::to_string(minutes) + "m";
    }
    return negative ? "-" + out : out;
}

TimeFormatter utc_formatter() {
    return [](std::int64_t seconds) { return format_utc(seconds); };
}

}  // namespace postmortem::text
