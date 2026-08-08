#include "commands/common.hpp"

#include <chrono>
#include <cstdio>

#include "core/input/values.hpp"
#include "platform/cpu_info.hpp"
#include "platform/eventlog.hpp"
#include "platform/os_info.hpp"

namespace postmortem::commands {
namespace {

// Spec §4.5 lists the providers the timeline correlates. WHEA alone is enough
// for scan and show.
const std::vector<std::string>& correlation_providers() {
    static const std::vector<std::string> providers{
        events::kWheaProvider,
        "Microsoft-Windows-Kernel-Power",
        "Microsoft-Windows-Kernel-Boot",
        "Microsoft-Windows-Kernel-General",
        "Microsoft-Windows-Kernel-Processor-Power",
        "Microsoft-Windows-WER-SystemErrorReporting",   // BugCheck 1001
        "EventLog",                                     // 6008, unexpected shutdown
        "Microsoft-Windows-Hyper-V-Hypervisor",
    };
    return providers;
}

std::int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Boot markers, used to spot records harvested from the previous session.
bool is_boot_marker(const events::Event& event) {
    if (event.provider == "Microsoft-Windows-Kernel-Boot") {
        return event.event_id == 20 || event.event_id == 27 || event.event_id == 24;
    }
    if (event.provider == "Microsoft-Windows-Kernel-General") {
        return event.event_id == 12;   // OS start
    }
    return false;
}

}  // namespace

void write_out(const std::string& text) {
    std::fwrite(text.data(), 1, text.size(), stdout);
}

void write_error(const std::string& message) {
    const std::string line = "pm: " + message + "\n";
    std::fwrite(line.data(), 1, line.size(), stderr);
}

text::TimeFormatter local_time_formatter() {
    return [](std::int64_t seconds) {
        std::string text = platform::format_local_time(seconds);
        return text.empty() ? text::format_utc(seconds) : text;
    };
}

EventLoad load_events(const cli::CommandLine& cmdline, const LoadOptions& options) {
    EventLoad load;

    platform::EventQuery query;
    query.limit = options.limit;
    query.providers = options.all_providers ? correlation_providers()
                                            : std::vector<std::string>{events::kWheaProvider};

    if (cmdline.global.evtx.has_value()) {
        query.evtx_path = *cmdline.global.evtx;
        load.source = *cmdline.global.evtx;
    } else {
        load.source = "the live System log";
    }

    if (const std::string* since = cmdline.option("since")) {
        const input::DurationResult duration = input::parse_duration(*since);
        if (!duration.ok) {
            load.error = "--since: " + duration.error;
            return load;
        }
        query.since = now_seconds() - duration.seconds;
        load.since = query.since;
    }

    const platform::EventQueryResult result = platform::query_events(query);
    if (!result.ok) {
        load.error = result.error;
        return load;
    }
    load.warnings = result.warnings;
    load.raw_events = result.events;

    // Decoding needs the vendor for the SMCA-specific fields. A saved .evtx
    // may well come from a different machine, so say so rather than assuming
    // this one's CPU applies.
    if (query.evtx_path.empty()) {
        load.vendor = platform::query_cpu_info().vendor;
    } else {
        load.vendor = cpu::Vendor::Unknown;
        load.warnings.emplace_back(
            "reading from a file, so the CPU vendor is unknown and the AMD SMCA layout is "
            "assumed for vendor-specific fields; pass the record to 'pm decode --vendor' if "
            "you know better");
    }

    std::vector<events::WheaRecord> records;
    for (const events::Event& event : result.events) {
        if (is_boot_marker(event)) load.boot_times.push_back(event.time);
        if (!events::is_whea_event(event)) continue;

        events::WheaRecord record = events::from_event(event);
        if (options.decode_records) events::decode(record, load.vendor);
        records.push_back(std::move(record));
    }

    load.incidents = events::cluster(std::move(records));

    // Fall back to this machine's boot time when the query found no boot
    // markers, which is common with a short --since window.
    if (load.boot_times.empty() && query.evtx_path.empty()) {
        load.boot_times.push_back(platform::query_os_info().boot_time);
    }
    events::mark_post_boot_harvest(load.incidents, load.boot_times);

    load.ok = true;
    return load;
}

void report_warnings(const EventLoad& load, const text::Style& style) {
    if (load.warnings.empty()) return;

    std::string out = "\n";
    out += text::heading("Notes", style);
    for (const std::string& warning : load.warnings) out += text::bullet(warning);
    write_out(out);
}

}  // namespace postmortem::commands
