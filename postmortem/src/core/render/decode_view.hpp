// Rendering for decoded MCA registers and CPER records (spec §6).
//
// Lives in core/ rather than commands/ for two reasons: it is pure, so the
// layout is unit-testable; and `scan`, `show` and `report` in later milestones
// present the same structures and must not grow their own private formatting.
//
// Spec §6 requirements this implements:
//   - bit fields as an aligned table of position, name, value and meaning
//   - the raw hex always beside the interpretation
//   - the verdict first, the evidence after
//   - uncertainty stated rather than smoothed over
//
// Named decode_view rather than decode because MSBuild puts every object file
// of a project in one flat directory: a second decode.cpp (commands/decode.cpp)
// would overwrite this one's decode.obj and the link would fail with a missing
// symbol. No two .cpp files in this repository may share a basename.

#pragma once

#include <string>

#include "core/cper/record.hpp"
#include "core/json/writer.hpp"
#include "core/mca/registers.hpp"
#include "core/text/table.hpp"

namespace postmortem::render {

struct Options {
    bool verbose = false;   // include hex dumps for recognised sections too
};

// --- MCA registers ---------------------------------------------------------

[[nodiscard]] std::string status_text(const mca::StatusDecode& decode, const text::Style& style);
[[nodiscard]] std::string address_text(const mca::AddressDecode& decode, const text::Style& style);
[[nodiscard]] std::string misc_text(const mca::MiscDecode& decode, const text::Style& style);

void status_json(const mca::StatusDecode& decode, json::Writer& writer);
void address_json(const mca::AddressDecode& decode, json::Writer& writer);
void misc_json(const mca::MiscDecode& decode, json::Writer& writer);

// --- CPER records ----------------------------------------------------------

[[nodiscard]] std::string record_text(const cper::Record& record, const text::Style& style,
                                      const Options& options);

void record_json(const cper::Record& record, json::Writer& writer);

// Formats a decoded field the way the field itself reads best: narrow fields
// in binary, because the spec writes encodings such as "TTLL" in binary, and
// wider ones in hex.
[[nodiscard]] std::string format_field_value(const mca::FieldRow& field);

}  // namespace postmortem::render
