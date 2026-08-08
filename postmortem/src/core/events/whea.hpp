// WHEA-Logger record typing and incident clustering (spec §4.1, §4.5).

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/cper/record.hpp"
#include "core/events/event.hpp"
#include "core/mca/registers.hpp"

namespace postmortem::events {

inline constexpr const char* kWheaProvider = "Microsoft-Windows-WHEA-Logger";

// The structured EventData fields spec §4.1 lists. Every one is optional: the
// set present depends on the error source and the Windows version.
struct WheaRecord {
    Event event;

    std::optional<unsigned> error_source;
    std::optional<unsigned> apic_id;
    std::optional<unsigned> mca_bank;
    std::optional<std::uint64_t> mci_stat;
    std::optional<std::uint64_t> mci_addr;
    std::optional<std::uint64_t> mci_misc;
    std::optional<unsigned> error_type;
    std::optional<unsigned> transaction_type;
    std::optional<unsigned> participation;
    std::optional<unsigned> request_type;
    std::optional<unsigned> memory_io;
    std::optional<unsigned> mem_hierarchy_level;
    std::optional<unsigned> timeout;
    std::optional<unsigned> operation_type;
    std::optional<unsigned> channel;
    std::optional<unsigned> length;

    std::vector<std::uint8_t> raw_data;   // the CPER blob, decoded from hex or base64
    std::string raw_data_format;          // "hex" / "base64" / "" when absent

    // Decoded on demand by decode(); empty until then.
    std::optional<mca::StatusDecode> status;
    std::optional<mca::AddressDecode> address;
    std::optional<mca::MiscDecode> misc;
    std::optional<cper::Record> cper;

    [[nodiscard]] bool is_uncorrected() const;
    [[nodiscard]] bool is_context_corrupt() const;
};

[[nodiscard]] bool is_whea_event(const Event& event);

// Types one event. Never fails: fields that are absent or unparseable stay
// empty, and the caller can still show the raw event.
[[nodiscard]] WheaRecord from_event(Event event);

// Fills in the MCA and CPER decodes. Separate from from_event() so that `scan`
// can list a hundred records cheaply and only `show` pays for full decoding.
void decode(WheaRecord& record, cpu::Vendor vendor);

// --- Incidents (spec §4.5) -------------------------------------------------
//
// "uncorrectable MCEs are broadcast to all cores, producing one record per
// processor - the tool must recognise this and present it as one incident with
// N reporting cores, not N incidents."

struct Incident {
    std::int64_t time = 0;              // earliest record in the cluster
    std::int64_t last_time = 0;
    std::vector<WheaRecord> records;

    std::vector<unsigned> apic_ids;     // sorted, deduplicated
    std::vector<unsigned> banks;        // sorted, deduplicated
    bool uncorrected = false;
    bool context_corrupt = false;
    bool overflow = false;

    // Spec §4.5: "MCA banks are sticky across warm reset, so a WHEA record
    // timestamped seconds after boot usually belongs to the *previous*
    // session's crash." Set when the incident falls inside the harvest window
    // after a boot; boot times come from the caller because they live in other
    // providers.
    bool post_boot_harvest = false;
    std::int64_t seconds_after_boot = 0;

    [[nodiscard]] std::string headline() const;
};

// Records within `window_seconds` of each other collapse into one incident.
// A broadcast MCE writes its records with identical timestamps, but the log
// can round them apart by a second, so the default is deliberately not zero.
[[nodiscard]] std::vector<Incident> cluster(std::vector<WheaRecord> records,
                                            std::int64_t window_seconds = 2);

// Marks incidents that landed shortly after a boot. `boot_times` need not be
// sorted.
void mark_post_boot_harvest(std::vector<Incident>& incidents,
                            const std::vector<std::int64_t>& boot_times,
                            std::int64_t window_seconds = 120);

}  // namespace postmortem::events
