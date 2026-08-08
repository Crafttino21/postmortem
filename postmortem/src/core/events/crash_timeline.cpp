#include "core/events/crash_timeline.hpp"

#include <algorithm>

#include "core/text/format.hpp"

namespace postmortem::events {
namespace {

using text::to_hex;

std::optional<std::uint64_t> field(const Event& event, std::string_view name) {
    return event.number(name);
}

// Kernel-Power 41 is the event that started this whole investigation: it fires
// on every unclean shutdown, and its BugcheckCode says whether Windows managed
// to bugcheck first.
TimelineEntry make_kernel_power_41(const Event& event) {
    TimelineEntry entry;
    entry.kind = EntryKind::UnexpectedShutdown;

    KernelPower41 detail;
    detail.bugcheck_code = field(event, "BugcheckCode");
    detail.power_button_timestamp = field(event, "PowerButtonTimestamp");
    detail.bugcheck_info_from_efi = field(event, "BugcheckInfoFromEFI");
    detail.whea_boot_error_count = field(event, "WHEABootErrorCount");
    entry.kernel_power = detail;

    const std::uint64_t code = detail.bugcheck_code.value_or(0);
    if (code == 0) {
        entry.summary = "the system rebooted without cleanly shutting down, and no bugcheck "
                        "code was recorded";
        entry.notes.emplace_back(
            "BugcheckCode 0 means Windows never got as far as a bugcheck. The machine was "
            "reset by something below the OS - a machine-check that corrupted processor "
            "context, a power event, or a watchdog. Look for a WHEA record harvested at the "
            "next boot.");
    } else {
        entry.summary = "the system rebooted without cleanly shutting down after bugcheck " +
                        to_hex(code, 0);
        entry.notes.emplace_back(
            "A non-zero BugcheckCode means Windows did bugcheck, so a crash dump may exist.");
    }

    if (detail.power_button_timestamp.value_or(0) != 0) {
        entry.notes.emplace_back(
            "PowerButtonTimestamp is non-zero, which points at the power button or a power "
            "loss rather than a fault.");
    }
    if (detail.whea_boot_error_count.value_or(0) > 0) {
        entry.notes.push_back(
            "WHEABootErrorCount is " + std::to_string(*detail.whea_boot_error_count) +
            ": firmware handed Windows that many error records at boot, which is direct "
            "evidence the previous session ended in a hardware error.");
    }
    return entry;
}

TimelineEntry classify(const Event& event) {
    TimelineEntry entry;
    entry.time = event.time;
    entry.provider = event.provider;
    entry.event_id = event.event_id;
    entry.kind = EntryKind::Other;
    entry.summary = event.provider + " event " + std::to_string(event.event_id);

    if (event.provider == "Microsoft-Windows-Kernel-Power" && event.event_id == 41) {
        TimelineEntry made = make_kernel_power_41(event);
        made.time = event.time;
        made.provider = event.provider;
        made.event_id = event.event_id;
        return made;
    }

    if (event.provider == "Microsoft-Windows-WER-SystemErrorReporting" &&
        event.event_id == 1001) {
        entry.kind = EntryKind::Bugcheck;
        entry.summary = "bugcheck reported";
        if (const std::string* text = event.value("param1")) {
            entry.summary = "bugcheck: " + *text;
        }
        return entry;
    }

    if (event.provider == "EventLog" && event.event_id == 6008) {
        entry.kind = EntryKind::DirtyShutdown;
        entry.summary = "the previous system shutdown was unexpected";
        // 6008 embeds the local time at which the previous session died, which
        // is often more precise than the event's own timestamp.
        std::string when;
        for (const auto& [name, value] : event.data) {
            (void)name;
            if (!value.empty()) {
                if (!when.empty()) when += " ";
                when += value;
            }
        }
        if (!when.empty()) {
            entry.notes.push_back("The log records the previous shutdown as: " + when +
                                  " (local time, as written by the event).");
        }
        return entry;
    }

    if (event.provider == "Microsoft-Windows-Kernel-Boot") {
        if (event.event_id == 20 || event.event_id == 27 || event.event_id == 24) {
            entry.kind = EntryKind::BootStart;
            entry.summary = "boot";
            return entry;
        }
        if (event.event_id == 124) {
            entry.kind = EntryKind::Other;
            entry.summary = "boot: virtualization-based security state reported";
            return entry;
        }
    }

    if (event.provider == "Microsoft-Windows-Kernel-General") {
        if (event.event_id == 12) {
            entry.kind = EntryKind::BootStart;
            entry.summary = "operating system started";
            return entry;
        }
        if (event.event_id == 13) {
            entry.kind = EntryKind::OsShutdown;
            entry.summary = "operating system shut down cleanly";
            return entry;
        }
    }

    if (event.provider == "Microsoft-Windows-Kernel-Processor-Power") {
        if (event.event_id == 37 || event.event_id == 55) {
            entry.kind = EntryKind::ThermalOrPowerLimit;
            entry.summary = event.event_id == 37
                                ? "a processor was throttled below its nominal frequency"
                                : "processor power management reported a limit";
            entry.notes.emplace_back(
                "Throttling is not itself a fault, but sustained throttling around the time of "
                "a reset points at thermals or power delivery rather than silicon.");
            return entry;
        }
    }

    if (event.provider == "Microsoft-Windows-Hyper-V-Hypervisor") {
        if (event.event_id == 41 || event.event_id == 42) {
            entry.kind = EntryKind::Hypervisor;
            entry.summary = "the hypervisor reported its launch state";
            return entry;
        }
    }

    return entry;
}

bool is_interesting(const TimelineEntry& entry) {
    // Everything the query returns that is not one of the classified kinds is
    // noise for this purpose; keeping it would bury the signal.
    return entry.kind != EntryKind::Other;
}

}  // namespace

std::string_view kind_text(EntryKind kind) {
    switch (kind) {
        case EntryKind::WheaIncident:        return "WHEA";
        case EntryKind::UnexpectedShutdown:  return "reset";
        case EntryKind::Bugcheck:            return "bugcheck";
        case EntryKind::DirtyShutdown:       return "dirty";
        case EntryKind::BootStart:           return "boot";
        case EntryKind::OsShutdown:          return "shutdown";
        case EntryKind::ThermalOrPowerLimit: return "throttle";
        case EntryKind::Hypervisor:          return "hyper-v";
        case EntryKind::Other:               break;
    }
    return "other";
}

Timeline build_timeline(const std::vector<Event>& events, std::vector<Incident> incidents) {
    Timeline timeline;
    timeline.incidents = std::move(incidents);

    for (const Event& event : events) {
        if (is_whea_event(event)) continue;   // folded in as incidents below
        TimelineEntry entry = classify(event);
        if (is_interesting(entry)) timeline.entries.push_back(std::move(entry));
    }

    for (std::size_t i = 0; i < timeline.incidents.size(); ++i) {
        const Incident& incident = timeline.incidents[i];
        TimelineEntry entry;
        entry.time = incident.time;
        entry.kind = EntryKind::WheaIncident;
        entry.provider = std::string(kWheaProvider);
        entry.incident_index = i;
        entry.summary = incident.headline();
        if (incident.post_boot_harvest) {
            entry.notes.push_back(
                "Written " + text::format_span(incident.seconds_after_boot) +
                " after boot. MCA banks are sticky across a warm reset, so this record almost "
                "certainly belongs to the session that just ended, not this one.");
        }
        timeline.entries.push_back(std::move(entry));
    }

    std::sort(timeline.entries.begin(), timeline.entries.end(),
              [](const TimelineEntry& a, const TimelineEntry& b) { return a.time < b.time; });

    // Collapse runs of the same thing at the same moment. A 32-core machine
    // logs Kernel-Processor-Power 55 once per logical processor, and the boot
    // markers arrive from Kernel-Boot and Kernel-General within the same
    // second; listing each separately buries everything that matters.
    {
        constexpr std::int64_t kCollapseWindow = 5;
        std::vector<TimelineEntry> collapsed;
        for (TimelineEntry& entry : timeline.entries) {
            const bool same_as_previous =
                !collapsed.empty() && collapsed.back().kind == entry.kind &&
                collapsed.back().summary == entry.summary &&
                entry.time - collapsed.back().time <= kCollapseWindow;

            if (same_as_previous) {
                ++collapsed.back().repeats;
                // Keep any note the duplicate carried that the first did not.
                for (std::string& note : entry.notes) {
                    if (std::find(collapsed.back().notes.begin(), collapsed.back().notes.end(),
                                  note) == collapsed.back().notes.end()) {
                        collapsed.back().notes.push_back(std::move(note));
                    }
                }
                continue;
            }
            collapsed.push_back(std::move(entry));
        }
        timeline.entries = std::move(collapsed);
    }

    // Walk once to assign sessions and count what happened in each.
    for (std::size_t i = 0; i < timeline.entries.size(); ++i) {
        TimelineEntry& entry = timeline.entries[i];

        if (entry.kind == EntryKind::BootStart) {
            // Consecutive boot markers from different providers describe one
            // boot; only start a session if the last one is not moments old.
            const bool same_boot = !timeline.sessions.empty() &&
                                   entry.time - timeline.sessions.back().start <= 60;
            if (!same_boot) {
                Session session;
                session.start = entry.time;
                session.first_entry = i;
                timeline.sessions.push_back(session);
            }
        }

        if (timeline.sessions.empty()) continue;   // events before the first boot marker
        entry.session = timeline.sessions.size() - 1;

        Session& session = timeline.sessions.back();
        session.end = entry.time;
        switch (entry.kind) {
            case EntryKind::UnexpectedShutdown:
            case EntryKind::DirtyShutdown:
                session.ended_unexpectedly = true;
                break;
            case EntryKind::Bugcheck:
                session.had_bugcheck = true;
                break;
            case EntryKind::WheaIncident:
                ++session.whea_incidents;
                break;
            default:
                break;
        }
    }

    // Headline (spec §6: conclusion in the first three lines).
    std::size_t resets_without_bugcheck = 0;
    std::size_t resets_with_bugcheck = 0;
    for (const TimelineEntry& entry : timeline.entries) {
        if (entry.kind != EntryKind::UnexpectedShutdown) continue;
        const std::uint64_t code =
            entry.kernel_power.has_value()
                ? entry.kernel_power->bugcheck_code.value_or(0)
                : 0;
        if (code == 0) {
            ++resets_without_bugcheck;
        } else {
            ++resets_with_bugcheck;
        }
    }

    if (resets_without_bugcheck == 0 && resets_with_bugcheck == 0) {
        timeline.headline = "No unexpected shutdown was recorded in this range.";
    } else {
        timeline.headline =
            std::to_string(resets_without_bugcheck + resets_with_bugcheck) +
            " unexpected shutdown(s): " + std::to_string(resets_without_bugcheck) +
            " with no bugcheck code and " + std::to_string(resets_with_bugcheck) +
            " with one.";
    }

    if (resets_without_bugcheck > 0 && !timeline.incidents.empty()) {
        timeline.notes.emplace_back(
            "A reset with BugcheckCode 0 alongside WHEA records is the signature this tool was "
            "built for: the CPU took an unrecoverable machine check with processor context "
            "corrupt, so it reset before Windows could write anything.");
    }
    if (resets_without_bugcheck > 0 && timeline.incidents.empty()) {
        timeline.notes.emplace_back(
            "Resets with no bugcheck code and no WHEA record at all point away from the CPU - "
            "consider power delivery, the PSU, or a board-level fault, none of which leave "
            "software evidence.");
    }

    return timeline;
}

}  // namespace postmortem::events
