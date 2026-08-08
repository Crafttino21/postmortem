// The event-record model (spec §4.1).
//
// Pure: an Event is built from rendered XML, never from an EVT_HANDLE, so the
// whole ingestion path above the Win32 call is testable against captured XML.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/xml/parse.hpp"

namespace postmortem::events {

struct Event {
    std::string provider;
    unsigned event_id = 0;
    unsigned level = 0;
    unsigned task = 0;
    std::string channel;
    std::string computer;

    std::int64_t time = 0;          // Unix seconds, UTC
    unsigned time_nanoseconds = 0;
    std::string time_text;          // as written in the XML

    std::uint64_t record_id = 0;
    std::uint64_t keywords = 0;

    // EventData / UserData children, in document order. Kept as strings
    // because the WHEA schema's types differ between Windows versions and the
    // interpretation belongs to whea.cpp, not here.
    std::vector<std::pair<std::string, std::string>> data;

    std::string xml;   // the original, for --verbose and for report --format md

    [[nodiscard]] const std::string* value(std::string_view name) const;
    [[nodiscard]] std::optional<std::uint64_t> number(std::string_view name) const;
};

// Builds an Event from a parsed <Event> element. Missing fields are left at
// their defaults rather than failing: event XML from different Windows builds
// carries different optional elements.
[[nodiscard]] Event from_xml(const xml::Node& event_node);

// Convenience: parse then convert. Returns nullopt only when the XML itself is
// unusable.
[[nodiscard]] std::optional<Event> from_xml_text(std::string_view text);

}  // namespace postmortem::events
