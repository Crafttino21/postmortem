// Per-core activity sampling via the Performance Data Helper (pdh.dll).
//
// This is as close to "watching the CPU work" as user mode gets without a
// kernel driver, which spec §2 rules out. Every counter here is documented and
// readable by a standard user: actual frequency, load, idle-state residency,
// interrupt and DPC rates, and core parking.
//
// C-state residency is the interesting one for this tool. The spec's whole
// thesis is idle-state instability, so seeing cores sink into C2/C3 at the
// moment a machine check lands is direct evidence for what `analyze` otherwise
// has to infer statistically.

#pragma once

#include <string>
#include <vector>

namespace postmortem::platform {

struct CoreSample {
    unsigned group = 0;
    unsigned index_in_group = 0;
    unsigned os_index = 0;

    double processor_time = 0;         // % busy
    double idle_time = 0;              // % idle
    double processor_performance = 0;  // % of nominal frequency
    double frequency_mhz = 0;

    // Idle-state residency as a percentage of the interval. Which of these
    // exist depends on the processor driver; absent ones stay at zero and are
    // named in PerfSnapshot::missing_counters.
    double c1_time = 0;
    double c2_time = 0;
    double c3_time = 0;

    double interrupts_per_sec = 0;
    double dpcs_per_sec = 0;
    bool parked = false;
};

struct PerfSnapshot {
    bool ok = false;
    std::string error;

    std::vector<CoreSample> cores;   // sorted by os_index
    CoreSample total;                // the _Total instance

    // Counters this machine does not publish. Reported rather than silently
    // shown as zero, which would read as "the cores never idle".
    std::vector<std::string> missing_counters;
};

// Holds an open PDH query. Rate counters need two collections to produce a
// value, so the first sample() after open() returns zeroes for those; the
// caller is expected to sample on a timer and discard nothing.
class PerfMonitor {
public:
    PerfMonitor() = default;
    ~PerfMonitor();

    PerfMonitor(const PerfMonitor&) = delete;
    PerfMonitor& operator=(const PerfMonitor&) = delete;

    [[nodiscard]] bool open(std::string& error);
    void close();
    [[nodiscard]] bool is_open() const { return query_ != nullptr; }

    [[nodiscard]] PerfSnapshot sample();

private:
    struct Counter;

    void* query_ = nullptr;                 // PDH_HQUERY
    std::vector<Counter*> counters_;
    std::vector<std::string> missing_;
    bool primed_ = false;                   // at least one collect has happened
};

}  // namespace postmortem::platform
