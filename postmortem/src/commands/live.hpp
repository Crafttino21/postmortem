#pragma once

#include "core/cli/args.hpp"
#include "core/text/table.hpp"

namespace postmortem::commands {

// `pm live` - a full-screen view of what the CPU is doing, refreshing until
// stopped.
//
// Not in the spec's command list; added on request. It is the closest a
// user-mode tool can get to watching the CPU work: per-core frequency, load,
// idle-state residency, interrupt and DPC rates from PDH, context switches and
// interrupt/DPC counts from an ETW kernel session when elevated, and any WHEA
// record appearing live. Instruction-level tracing would need a driver, which
// spec §2 forbids.
[[nodiscard]] int run_live(const cli::CommandLine& cmdline, const text::Style& style);

}  // namespace postmortem::commands
