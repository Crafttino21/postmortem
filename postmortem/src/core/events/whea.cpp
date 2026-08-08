#include "core/events/whea.hpp"

#include <algorithm>

#include "core/input/values.hpp"

namespace postmortem::events {
namespace {

std::optional<unsigned> unsigned_field(const Event& event, std::string_view name) {
    const auto value = event.number(name);
    if (!value.has_value()) return std::nullopt;
    return static_cast<unsigned>(*value);
}

// The RawData field is rendered as a hex string by EvtRender, and as base64 in
// some exports. parse_blob settles which without being told.
void read_raw_data(const Event& event, WheaRecord& record) {
    const std::string* text = event.value("RawData");
    if (text == nullptr || text->empty()) return;

    const input::BlobResult blob = input::parse_blob(*text);
    if (!blob.ok) return;
    record.raw_data = blob.bytes;
    record.raw_data_format = blob.format;
}

void unique_sorted(std::vector<unsigned>& values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

}  // namespace

bool WheaRecord::is_uncorrected() const {
    if (status.has_value()) return status->flags.uncorrected;
    if (mci_stat.has_value()) return ((*mci_stat >> 61) & 1u) != 0;
    return false;
}

bool WheaRecord::is_context_corrupt() const {
    if (status.has_value()) return status->flags.context_corrupt;
    if (mci_stat.has_value()) return ((*mci_stat >> 57) & 1u) != 0;
    return false;
}

bool is_whea_event(const Event& event) {
    return event.provider == kWheaProvider;
}

WheaRecord from_event(Event event) {
    WheaRecord record;

    record.error_source = unsigned_field(event, "ErrorSource");
    record.apic_id = unsigned_field(event, "ApicId");
    record.mca_bank = unsigned_field(event, "MCABank");
    record.mci_stat = event.number("MciStat");
    record.mci_addr = event.number("MciAddr");
    record.mci_misc = event.number("MciMisc");
    record.error_type = unsigned_field(event, "ErrorType");
    record.transaction_type = unsigned_field(event, "TransactionType");
    record.participation = unsigned_field(event, "Participation");
    record.request_type = unsigned_field(event, "RequestType");
    record.memory_io = unsigned_field(event, "MemorIO");   // spelled thus in the schema
    record.mem_hierarchy_level = unsigned_field(event, "MemHierarchyLvl");
    record.timeout = unsigned_field(event, "Timeout");
    record.operation_type = unsigned_field(event, "OperationType");
    record.channel = unsigned_field(event, "Channel");
    record.length = unsigned_field(event, "Length");

    read_raw_data(event, record);

    record.event = std::move(event);
    return record;
}

void decode(WheaRecord& record, cpu::Vendor vendor) {
    if (record.mci_stat.has_value()) {
        record.status = mca::decode_status(*record.mci_stat, vendor);
    }
    if (record.mci_addr.has_value()) {
        record.address = mca::decode_address(*record.mci_addr, vendor);
    }
    if (record.mci_misc.has_value()) {
        const bool misc_valid = record.status.has_value() ? record.status->flags.misc_valid : true;
        record.misc = mca::decode_misc(*record.mci_misc, vendor, misc_valid);
    }
    if (!record.raw_data.empty()) {
        record.cper = cper::decode_record(record.raw_data);
    }
}

std::string Incident::headline() const {
    const std::string cores =
        std::to_string(apic_ids.size()) + (apic_ids.size() == 1 ? " core" : " cores");

    if (uncorrected && context_corrupt) {
        return "unrecoverable machine check, processor context corrupt, reported by " + cores +
               "; no bugcheck and no crash dump was possible";
    }
    if (uncorrected) {
        return "uncorrected machine check reported by " + cores +
               "; a bugcheck 0x124 would be expected";
    }
    if (!records.empty()) {
        return "corrected machine check reported by " + cores + "; logged for trending";
    }
    return "empty incident";
}

std::vector<Incident> cluster(std::vector<WheaRecord> records, std::int64_t window_seconds) {
    std::sort(records.begin(), records.end(), [](const WheaRecord& a, const WheaRecord& b) {
        if (a.event.time != b.event.time) return a.event.time < b.event.time;
        return a.event.record_id < b.event.record_id;
    });

    std::vector<Incident> incidents;
    for (WheaRecord& record : records) {
        const bool extend = !incidents.empty() &&
                            record.event.time - incidents.back().last_time <= window_seconds;
        if (!extend) {
            Incident incident;
            incident.time = record.event.time;
            incident.last_time = record.event.time;
            incidents.push_back(std::move(incident));
        }

        Incident& incident = incidents.back();
        incident.last_time = std::max(incident.last_time, record.event.time);
        if (record.apic_id.has_value()) incident.apic_ids.push_back(*record.apic_id);
        if (record.mca_bank.has_value()) incident.banks.push_back(*record.mca_bank);
        if (record.is_uncorrected()) incident.uncorrected = true;
        if (record.is_context_corrupt()) incident.context_corrupt = true;
        if (record.mci_stat.has_value() && ((*record.mci_stat >> 62) & 1u) != 0) {
            incident.overflow = true;
        }
        incident.records.push_back(std::move(record));
    }

    for (Incident& incident : incidents) {
        unique_sorted(incident.apic_ids);
        unique_sorted(incident.banks);
    }
    return incidents;
}

void mark_post_boot_harvest(std::vector<Incident>& incidents,
                            const std::vector<std::int64_t>& boot_times,
                            std::int64_t window_seconds) {
    if (boot_times.empty()) return;

    std::vector<std::int64_t> sorted = boot_times;
    std::sort(sorted.begin(), sorted.end());

    for (Incident& incident : incidents) {
        // The most recent boot at or before the incident.
        const auto next = std::upper_bound(sorted.begin(), sorted.end(), incident.time);
        if (next == sorted.begin()) continue;
        const std::int64_t boot = *(next - 1);

        incident.seconds_after_boot = incident.time - boot;
        if (incident.seconds_after_boot >= 0 && incident.seconds_after_boot <= window_seconds) {
            incident.post_boot_harvest = true;
        }
    }
}

}  // namespace postmortem::events
