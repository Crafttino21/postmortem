// Parsing for values a user pastes in (spec §5).
//
// "`decode` operating on a value pasted from someone else's event log - with
// no access to that machine - must work. That is a core use case, not an
// extra." So this has to cope with what people actually paste: hex with
// spaces and newlines from Event Viewer's Details pane, a C array with 0x
// prefixes and commas, base64 from the event XML, or a decimal number from the
// friendly view.
//
// Pure, so it is unit-tested without a machine or a file.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace postmortem::input {

struct BlobResult {
    bool ok = false;
    std::vector<std::uint8_t> bytes;
    std::string format;   // "hex" or "base64", for the output to state
    std::string error;
};

// Decodes a pasted binary blob. Tries hex first, since spec §5 documents
// `--cper <hex|@file>`; falls back to base64, which is how the event XML
// carries the same data.
[[nodiscard]] BlobResult parse_blob(std::string_view text);

struct IntegerResult {
    bool ok = false;
    std::uint64_t value = 0;
    int base = 0;   // 16, 10 or 2, so the caller can report how it was read
    std::string error;
};

// Parses a register value. "0x..." is hex, "0b..." is binary, digits alone are
// decimal (that is what Event Viewer's friendly view shows), and anything
// containing a-f is hex. The base used is reported so the output can echo it -
// misreading the base would produce a confidently wrong diagnosis, which spec
// §6 rates worse than an admitted gap.
[[nodiscard]] IntegerResult parse_u64(std::string_view text);

struct DurationResult {
    bool ok = false;
    std::int64_t seconds = 0;
    std::string error;
};

// "90d", "12h", "30m", "6w", "1y", or plain digits meaning days - the form
// spec §5 writes as `--since 90d`.
[[nodiscard]] DurationResult parse_duration(std::string_view text);

}  // namespace postmortem::input
