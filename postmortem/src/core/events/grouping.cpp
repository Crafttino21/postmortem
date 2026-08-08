#include "core/events/grouping.hpp"

#include <algorithm>
#include <map>

#include "core/text/format.hpp"

namespace postmortem::events {
namespace {

using text::to_hex;

std::string optional_number(const std::optional<unsigned>& value) {
    return value.has_value() ? std::to_string(*value) : std::string("-");
}

}  // namespace

const std::vector<GroupFieldSpec>& group_field_specs() {
    static const std::vector<GroupFieldSpec> specs{
        {"apic", GroupField::Apic, "APIC", "reporting logical processor"},
        {"bank", GroupField::Bank, "Bank", "MCA bank number"},
        {"event", GroupField::EventId, "Event", "WHEA-Logger event ID (17/18/19/20/47)"},
        {"type", GroupField::ErrorType, "Type", "the ErrorType field"},
        {"transaction", GroupField::TransactionType, "Txn", "the TransactionType field"},
        {"status", GroupField::Status, "MciStat", "the whole MCA_STATUS value"},
        {"code", GroupField::ErrorCode, "Code", "MCA_STATUS[15:0], the compound error code"},
        {"address", GroupField::Address, "MciAddr", "the whole MCA_ADDR value"},
        {"page", GroupField::AddressPage, "Page", "the 4 KiB page the address falls in"},
        {"class", GroupField::AddressClass, "Class", "user / kernel / physical"},
        {"severity", GroupField::Severity, "Severity", "corrected, uncorrected or fatal"},
        {"day", GroupField::Day, "Day", "calendar day, local time"},
        {"hour", GroupField::Hour, "Hour", "hour of day, local time"},
    };
    return specs;
}

std::optional<GroupField> parse_group_field(std::string_view name) {
    for (const GroupFieldSpec& spec : group_field_specs()) {
        if (spec.name == name) return spec.field;
    }
    return std::nullopt;
}

std::string_view group_field_header(GroupField field) {
    for (const GroupFieldSpec& spec : group_field_specs()) {
        if (spec.field == field) return spec.header;
    }
    return "?";
}

GroupFieldList parse_group_fields(std::string_view text) {
    GroupFieldList result;

    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t comma = text.find(',', start);
        const std::size_t end = comma == std::string_view::npos ? text.size() : comma;

        std::string_view name = text.substr(start, end - start);
        while (!name.empty() && name.front() == ' ') name.remove_prefix(1);
        while (!name.empty() && name.back() == ' ') name.remove_suffix(1);

        if (!name.empty()) {
            const auto field = parse_group_field(name);
            if (!field.has_value()) {
                result.error = "unknown group field '" + std::string(name) + "'";
                return result;
            }
            result.fields.push_back(*field);
        }

        if (comma == std::string_view::npos) break;
        start = comma + 1;
    }

    if (result.fields.empty()) {
        result.error = "no fields given";
        return result;
    }
    result.ok = true;
    return result;
}

std::string field_value(const WheaRecord& record, GroupField field, cpu::Vendor vendor,
                        const std::function<std::string(std::int64_t)>& format_time) {
    switch (field) {
        case GroupField::Apic:
            return optional_number(record.apic_id);
        case GroupField::Bank:
            return optional_number(record.mca_bank);
        case GroupField::EventId:
            return std::to_string(record.event.event_id);
        case GroupField::ErrorType:
            return optional_number(record.error_type);
        case GroupField::TransactionType:
            return optional_number(record.transaction_type);
        case GroupField::Status:
            return record.mci_stat.has_value() ? to_hex(*record.mci_stat, 16) : "-";
        case GroupField::ErrorCode:
            return record.mci_stat.has_value()
                       ? to_hex(*record.mci_stat & 0xFFFFull, 4)
                       : "-";
        case GroupField::Address:
            return record.mci_addr.has_value() ? to_hex(*record.mci_addr, 16) : "-";
        case GroupField::AddressPage: {
            if (!record.mci_addr.has_value()) return "-";
            const mca::AddressDecode decode = mca::decode_address(*record.mci_addr, vendor);
            return to_hex(decode.sign_extended >> 12, 12);
        }
        case GroupField::AddressClass: {
            if (!record.mci_addr.has_value()) return "-";
            const mca::AddressDecode decode = mca::decode_address(*record.mci_addr, vendor);
            switch (decode.classification) {
                case mca::AddressClass::UserVirtual:     return "user VA";
                case mca::AddressClass::KernelVirtual:   return "kernel VA";
                case mca::AddressClass::PhysicalOrIndex: return "physical";
                case mca::AddressClass::NoAddress:       return "none";
            }
            return "-";
        }
        case GroupField::Severity:
            if (record.is_uncorrected()) {
                return record.is_context_corrupt() ? "fatal" : "uncorrected";
            }
            return "corrected";
        case GroupField::Day: {
            // format_time yields "YYYY-MM-DD HH:MM:SS"; slicing it keeps the
            // timezone decision with the caller.
            const std::string text = format_time(record.event.time);
            return text.size() >= 10 ? text.substr(0, 10) : text;
        }
        case GroupField::Hour: {
            const std::string text = format_time(record.event.time);
            return text.size() >= 13 ? text.substr(11, 2) + ":00" : text;
        }
    }
    return "-";
}

Grouping group_records(const std::vector<const WheaRecord*>& records,
                       const std::vector<GroupField>& fields, cpu::Vendor vendor,
                       const std::function<std::string(std::int64_t)>& format_time) {
    Grouping grouping;
    grouping.fields = fields;

    std::map<std::vector<std::string>, GroupRow> rows;
    for (const WheaRecord* record : records) {
        if (record == nullptr) continue;
        ++grouping.total_records;

        std::vector<std::string> key;
        key.reserve(fields.size());
        for (const GroupField field : fields) {
            key.push_back(field_value(*record, field, vendor, format_time));
        }

        GroupRow& row = rows[key];
        if (row.count == 0) {
            row.key = key;
            row.first_seen = record->event.time;
            row.last_seen = record->event.time;
        } else {
            row.first_seen = std::min(row.first_seen, record->event.time);
            row.last_seen = std::max(row.last_seen, record->event.time);
        }
        ++row.count;
    }

    grouping.rows.reserve(rows.size());
    for (auto& [key, row] : rows) {
        (void)key;
        grouping.rows.push_back(row);
    }

    // Most frequent first, then by key so equal counts have a stable order.
    std::sort(grouping.rows.begin(), grouping.rows.end(),
              [](const GroupRow& a, const GroupRow& b) {
                  if (a.count != b.count) return a.count > b.count;
                  return a.key < b.key;
              });
    return grouping;
}

}  // namespace postmortem::events
