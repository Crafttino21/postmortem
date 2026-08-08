#pragma once

#include "core/cli/args.hpp"
#include "core/text/table.hpp"

namespace postmortem::commands {

// `pm mitigate list|apply|revert <name>` (spec §4.9, §8 milestone 8).
//
// Every mutation is snapshotted to %ProgramData%\postmortem\state.json before
// it happens, is reversible from that snapshot rather than from a hardcoded
// default, and is gated behind an interactive confirmation or --yes.
[[nodiscard]] int run_mitigate(const cli::CommandLine& cmdline, const text::Style& style);

}  // namespace postmortem::commands
