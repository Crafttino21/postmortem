// Rendering for WHEA incidents (spec §4.5, §6).

#pragma once

#include <string>
#include <vector>

#include "core/events/whea.hpp"
#include "core/json/writer.hpp"
#include "core/text/format.hpp"
#include "core/text/table.hpp"

namespace postmortem::render {

struct IncidentOptions {
    bool verbose = false;
    text::TimeFormatter time = text::utc_formatter();
};

// One line per incident, with the reporting-core count rather than one row per
// broadcast record.
[[nodiscard]] std::string incident_table(const std::vector<events::Incident>& incidents,
                                         const text::Style& style,
                                         const IncidentOptions& options);

// Everything about one incident: every record, the MCA decode, and the CPER
// sections. This is what `pm show` prints.
[[nodiscard]] std::string incident_detail(const events::Incident& incident, std::size_t index,
                                          const text::Style& style,
                                          const IncidentOptions& options);

void incident_json(const events::Incident& incident, json::Writer& writer, bool include_decodes);

}  // namespace postmortem::render
