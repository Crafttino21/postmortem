// Frame rendering for `pm live`.
//
// Pure: takes a snapshot struct, returns the text of one frame. Keeping it out
// of the command means the layout can be unit-tested without a console, a
// performance counter or an ETW session.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/text/table.hpp"

namespace postmortem::render {

// One logical processor's row. Deliberately not the platform struct: the
// renderer must not depend on PDH or ETW types.
struct LiveCore {
    unsigned os_index = 0;
    double frequency_mhz = 0;
    double performance_percent = 0;
    double busy_percent = 0;
    double c1_percent = 0;
    double c2_percent = 0;
    double c3_percent = 0;
    bool parked = false;

    double interrupts_per_sec = 0;
    double dpcs_per_sec = 0;

    // From ETW, when a session is running.
    std::optional<double> context_switches_per_sec;
    std::optional<double> etw_dpcs_per_sec;
    std::optional<double> etw_interrupts_per_sec;

    // Physical mapping, when the topology could be resolved.
    std::optional<unsigned> core_id;
    std::optional<unsigned> thread_id;
    std::optional<unsigned> l3_complex;
};

struct LiveIncident {
    std::string when;
    std::string text;
    bool fatal = false;
};

struct LiveSnapshot {
    std::string cpu_brand;
    unsigned nominal_mhz = 0;
    std::string uptime;
    std::string clock;              // wall-clock time of this frame

    std::vector<LiveCore> cores;
    double total_busy_percent = 0;

    bool etw_active = false;
    std::string etw_note;           // why ETW is off, when it is
    double interval_seconds = 1.0;

    // Historical WHEA count plus anything that arrived while watching.
    std::size_t known_incidents = 0;
    std::vector<LiveIncident> live_incidents;

    std::vector<std::string> notes;   // missing counters and similar
    bool paused = false;
    unsigned sort_by_activity = 0;    // 0 = by index, 1 = busiest first
};

// Renders one frame, clipped to `rows` so it never scrolls the alternate
// buffer. `columns` controls how wide the activity bars are drawn.
[[nodiscard]] std::string live_frame(const LiveSnapshot& snapshot, const text::Style& style,
                                     unsigned columns, unsigned rows);

}  // namespace postmortem::render
