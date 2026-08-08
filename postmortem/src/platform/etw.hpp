// Real-time kernel tracing (spec §2: documented Win32 only, no driver).
//
// ETW is the closest Windows lets user mode get to watching the CPU execute:
// the kernel logger reports every context switch, every DPC and every
// interrupt, tagged with the processor it happened on. That is scheduler-level
// rather than instruction-level - Intel PT or AMD IBS would be needed for the
// latter, and both require a driver - but it is real activity, not a sampled
// average.
//
// Requires elevation. Everything here fails softly: if the session cannot be
// started, the caller falls back to the PDH view and says why.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace postmortem::platform {

// Counts accumulated since the previous call to take(), per processor index.
struct EtwCounts {
    std::vector<std::uint64_t> context_switches;
    std::vector<std::uint64_t> dpcs;
    std::vector<std::uint64_t> interrupts;

    std::uint64_t total_context_switches = 0;
    std::uint64_t total_dpcs = 0;
    std::uint64_t total_interrupts = 0;

    // Events the consumer could not attribute to a processor. Non-zero here
    // means the totals are right but the per-core split is incomplete.
    std::uint64_t unattributed = 0;
};

class EtwSession {
public:
    // Public because ETW's callbacks are free functions that receive it as the
    // user context; they cannot reach a private nested type.
    struct Impl;

    EtwSession() = default;
    ~EtwSession();

    EtwSession(const EtwSession&) = delete;
    EtwSession& operator=(const EtwSession&) = delete;

    // Starts the NT Kernel Logger with context-switch, DPC and interrupt
    // tracing. Returns false and fills `error` when that is not possible -
    // most often because the process is not elevated, or because something
    // else already owns the kernel logger (only one exists system-wide).
    [[nodiscard]] bool start(unsigned processor_count, std::string& error);
    void stop();
    [[nodiscard]] bool running() const { return running_; }

    // Snapshot and reset the counters.
    [[nodiscard]] EtwCounts take();

private:
    Impl* impl_ = nullptr;
    bool running_ = false;
};

}  // namespace postmortem::platform
