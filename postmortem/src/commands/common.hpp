// Plumbing shared by the commands that read the event log.
//
// Loading and clustering WHEA records is identical for scan, show, timeline,
// analyze and report; only the presentation differs. Keeping it here means the
// `--since` and `--evtx` semantics cannot drift between them.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/cli/args.hpp"
#include "core/events/whea.hpp"
#include "core/text/format.hpp"
#include "core/text/table.hpp"

namespace postmortem::commands {

namespace exit_code {
constexpr int kSuccess = 0;
constexpr int kFailure = 1;
constexpr int kUsage = 2;
constexpr int kUnsupportedHost = 3;
constexpr int kNeedsElevation = 4;
}  // namespace exit_code

void write_out(const std::string& text);
void write_error(const std::string& message);

// Local-time formatter, so displayed timestamps match what the user sees in
// Event Viewer. JSON output always uses UTC instead.
[[nodiscard]] text::TimeFormatter local_time_formatter();

struct EventLoad {
    bool ok = false;
    std::string error;
    std::vector<std::string> warnings;

    std::vector<events::Incident> incidents;
    std::vector<events::Event> raw_events;   // every event the query returned

    // Boot times harvested from the same query, used to mark post-boot
    // harvesting (spec §4.5).
    std::vector<std::int64_t> boot_times;

    cpu::Vendor vendor = cpu::Vendor::Unknown;
    std::string source;        // "the live System log" or the .evtx path
    std::int64_t since = 0;    // 0 when unbounded
};

struct LoadOptions {
    bool decode_records = false;   // run the MCA and CPER decoders on every record
    bool all_providers = false;    // for timeline: fetch the correlation providers too
    std::size_t limit = 0;
};

// Reads `--since` and `--evtx` off the command line, queries, types, clusters.
[[nodiscard]] EventLoad load_events(const cli::CommandLine& cmdline, const LoadOptions& options);

// Prints the query's non-fatal warnings, if any.
void report_warnings(const EventLoad& load, const text::Style& style);

}  // namespace postmortem::commands
