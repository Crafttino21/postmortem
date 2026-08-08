// Frame rendering for the two live inspection views (`pm live --stacks` and
// `pm watch-mem`). Pure, so the layout is testable without ETW or a process.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/text/table.hpp"

namespace postmortem::render {

// --- Sampled stacks --------------------------------------------------------

struct StackFrameLine {
    std::string text;      // already symbolised
    bool kernel = false;
};

struct HotStack {
    std::uint64_t count = 0;
    double share_percent = 0;
    std::uint32_t process_id = 0;
    std::string process_name;
    std::vector<StackFrameLine> frames;   // innermost first
};

struct StackSnapshot {
    std::vector<HotStack> stacks;
    std::uint64_t total_samples = 0;
    std::uint64_t kernel_samples = 0;
    std::uint64_t user_samples = 0;
    std::uint64_t dropped = 0;
    bool symbols_available = false;
    unsigned depth = 4;                   // frames shown per stack
    std::vector<std::string> notes;
};

[[nodiscard]] std::string stack_frame(const StackSnapshot& snapshot, const text::Style& style,
                                      unsigned columns, unsigned rows);

// --- Memory watch ----------------------------------------------------------

struct MemoryWatch {
    std::uint32_t process_id = 0;
    std::string process_name;
    std::uint64_t address = 0;
    std::string address_label;     // e.g. "myapp.exe+0x1000", when known
    std::string clock;
    double interval_seconds = 1.0;
    bool paused = false;

    std::vector<std::uint8_t> bytes;
    std::size_t readable = 0;      // how many of them could be read

    // Parallel to `bytes`: true where the byte differs from the previous tick.
    std::vector<bool> changed_now;
    // How many times each offset has ever changed since the watch started.
    std::vector<std::uint32_t> change_counts;

    std::uint64_t ticks = 0;
    std::string error;             // set when the last read failed entirely
};

[[nodiscard]] std::string memory_frame(const MemoryWatch& watch, const text::Style& style,
                                       unsigned columns, unsigned rows);

}  // namespace postmortem::render
