#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace postmortem::text {

// "0x" followed by uppercase hex. `digits` zero-pads to a fixed width, which
// matters throughout this tool: an MCA_STATUS printed as 0xBEA0000000000108 is
// checkable against the event log, one printed as 0xbea...108 is not.
[[nodiscard]] std::string to_hex(std::uint64_t value, int digits = 0);

// Classic 16-bytes-per-line dump with an ASCII gutter. Spec §4.2 requires
// unknown CPER section bodies to be emitted this way rather than dropped, so
// a record containing a vendor-private section is still fully re-verifiable by
// whoever reads the report.
//
// `base_offset` is added to the printed offsets, so a section body can show
// its position within the whole record.
[[nodiscard]] std::string hex_dump(std::span<const std::uint8_t> bytes,
                                   std::size_t base_offset = 0, std::size_t indent = 2);

// --- Time ------------------------------------------------------------------
//
// Event XML carries timestamps as "2026-08-08T13:46:22.1234567Z". Parsing them
// here rather than through the C library keeps the event model in core/, where
// it is testable without an event log; the sub-second part is kept separately
// because §4.5 has to decide whether two records share a timestamp.

struct Instant {
    std::int64_t seconds = 0;    // Unix seconds, UTC
    unsigned nanoseconds = 0;
};

[[nodiscard]] std::optional<Instant> parse_iso8601(std::string_view text);

// "2026-08-08 13:46:22Z". Stable across machines, so it is what JSON output
// uses; display uses the local-time formatter in the platform layer.
[[nodiscard]] std::string format_utc(std::int64_t unix_seconds);

// "12d 4h 33m", or "48s" for short spans.
[[nodiscard]] std::string format_span(std::int64_t seconds);

// How a Unix timestamp is turned into display text. The platform layer
// installs a local-time formatter; core defaults to UTC so that rendering
// stays pure and testable.
using TimeFormatter = std::function<std::string(std::int64_t)>;

[[nodiscard]] TimeFormatter utc_formatter();

}  // namespace postmortem::text
