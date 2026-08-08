#pragma once

#include "core/cli/args.hpp"
#include "core/text/table.hpp"
#include "platform/cpu_topology.hpp"

namespace postmortem::commands {

// `pm topology` - APIC ID to core/thread/CCD map.
[[nodiscard]] int run_topology(const cli::CommandLine& cmdline, const text::Style& style);

}  // namespace postmortem::commands
