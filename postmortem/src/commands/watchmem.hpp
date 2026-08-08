#pragma once

#include "core/cli/args.hpp"
#include "core/text/table.hpp"

namespace postmortem::commands {

// `pm watch-mem` - a live hex view of a region of another process's memory,
// highlighting bytes as they change.
//
// Read-only and never suspends the target: ReadProcessMemory works on a
// running process. The cost is that a multi-byte value can be caught mid-write
// and read torn.
[[nodiscard]] int run_watch_mem(const cli::CommandLine& cmdline, const text::Style& style);

}  // namespace postmortem::commands
