// Frequency tallies over WHEA records.
//
// `pm scan` collapses a broadcast machine check into one incident, which is
// right for reading a history but wrong for two other jobs: seeing every raw
// record as logged, and counting how often a given combination recurs. This
// module covers the second - the equivalent of
//
//   Get-WinEvent ... | Group-Object Id,Bank,Apic | Sort-Object Count -Descending
//
// but over fields the tool has already decoded, so grouping by the MCA_STATUS
// value or by the page an address falls in is just as easy as grouping by
// APIC ID.

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/events/whea.hpp"

namespace postmortem::events {

enum class GroupField {
    Apic,
    Bank,
    EventId,
    ErrorType,
    TransactionType,
    Status,          // the whole MCA_STATUS value
    ErrorCode,       // MCA_STATUS[15:0]
    Address,         // the whole MCA_ADDR value
    AddressPage,     // the 4 KiB page the address falls in
    AddressClass,    // user / kernel / physical
    Severity,
    Day,
    Hour,
};

struct GroupFieldSpec {
    std::string_view name;
    GroupField field;
    std::string_view header;
    std::string_view description;
};

[[nodiscard]] const std::vector<GroupFieldSpec>& group_field_specs();
[[nodiscard]] std::optional<GroupField> parse_group_field(std::string_view name);
[[nodiscard]] std::string_view group_field_header(GroupField field);

// Parses a comma-separated list, e.g. "event,bank,apic". Reports the offending
// name rather than silently ignoring it.
struct GroupFieldList {
    bool ok = false;
    std::vector<GroupField> fields;
    std::string error;
};
[[nodiscard]] GroupFieldList parse_group_fields(std::string_view text);

struct GroupRow {
    std::vector<std::string> key;   // one entry per requested field
    std::size_t count = 0;
    std::int64_t first_seen = 0;
    std::int64_t last_seen = 0;
};

struct Grouping {
    std::vector<GroupField> fields;
    std::vector<GroupRow> rows;   // most frequent first
    std::size_t total_records = 0;
};

// `format_time` turns a Unix timestamp into "YYYY-MM-DD HH:MM:SS" in whatever
// zone the caller wants; the Day and Hour fields slice that text rather than
// carrying a timezone database into core.
[[nodiscard]] Grouping group_records(const std::vector<const WheaRecord*>& records,
                                     const std::vector<GroupField>& fields,
                                     cpu::Vendor vendor,
                                     const std::function<std::string(std::int64_t)>& format_time);

// The value a single record contributes to one field, already formatted.
[[nodiscard]] std::string field_value(const WheaRecord& record, GroupField field,
                                      cpu::Vendor vendor,
                                      const std::function<std::string(std::int64_t)>& format_time);

}  // namespace postmortem::events
