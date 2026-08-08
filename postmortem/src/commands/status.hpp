#pragma once

#include "core/cli/args.hpp"
#include "core/text/table.hpp"

namespace postmortem::commands {

// `pm status` (spec §4.8). Milestone 1 covers CPU, firmware and OS; the
// crash-dump, power, virtualization and DIMM sections arrive with the
// milestones that also learn to change those settings.
[[nodiscard]] int run_status(const cli::CommandLine& cmdline, const text::Style& style);

}  // namespace postmortem::commands
