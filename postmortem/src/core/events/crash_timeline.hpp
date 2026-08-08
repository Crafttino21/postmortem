// Merged, chronological crash timeline (spec §4.5).
//
// "The single most useful output." The point is not to list events but to say
// what each one means for the investigation: which boot each belongs to,
// whether Kernel-Power 41 reported a bugcheck code or zero, and whether a WHEA
// record describes this session or the previous one.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/events/event.hpp"
#include "core/events/whea.hpp"

namespace postmortem::events {

enum class EntryKind {
    WheaIncident,
    UnexpectedShutdown,   // Kernel-Power 41
    Bugcheck,             // BugCheck 1001
    DirtyShutdown,        // EventLog 6008
    BootStart,            // Kernel-Boot 20/27, Kernel-General 12
    OsShutdown,           // Kernel-General 13
    ThermalOrPowerLimit,  // Kernel-Processor-Power 37/55
    Hypervisor,           // Hyper-V-Hypervisor 41/42
    Other,
};

[[nodiscard]] std::string_view kind_text(EntryKind kind);

struct KernelPower41 {
    std::optional<std::uint64_t> bugcheck_code;
    std::optional<std::uint64_t> power_button_timestamp;
    std::optional<std::uint64_t> bugcheck_info_from_efi;
    std::optional<std::uint64_t> whea_boot_error_count;
};

struct TimelineEntry {
    std::int64_t time = 0;
    EntryKind kind = EntryKind::Other;

    std::string provider;
    unsigned event_id = 0;

    std::string summary;              // one line, already interpreted
    std::vector<std::string> notes;   // the "why this matters" detail

    // How many identical events collapsed into this row. Kernel-Processor-Power
    // fires once per logical processor and the boot markers arrive from three
    // providers at the same instant, so without this the timeline is 90% noise.
    std::size_t repeats = 1;

    // Set for EntryKind::WheaIncident; index into the incident list.
    std::optional<std::size_t> incident_index;
    std::optional<KernelPower41> kernel_power;

    // Which boot session this entry belongs to; 0 is the earliest seen.
    std::optional<std::size_t> session;
};

// One power cycle: from a boot marker to the next.
struct Session {
    std::int64_t start = 0;
    std::optional<std::int64_t> end;       // last event seen before the next boot
    bool ended_unexpectedly = false;       // a 41 or 6008 followed
    bool had_bugcheck = false;
    std::size_t whea_incidents = 0;
    std::size_t first_entry = 0;           // index into Timeline::entries
};

struct Timeline {
    std::vector<TimelineEntry> entries;
    std::vector<Session> sessions;
    std::vector<Incident> incidents;

    // The headline: how many unexplained resets, how many with a bugcheck.
    std::string headline;
    std::vector<std::string> notes;
};

// Builds the timeline from every event the query returned plus the already
// clustered WHEA incidents.
[[nodiscard]] Timeline build_timeline(const std::vector<Event>& events,
                                      std::vector<Incident> incidents);

}  // namespace postmortem::events
