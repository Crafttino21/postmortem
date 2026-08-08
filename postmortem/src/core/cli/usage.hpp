#pragma once

#include <string>

#include "core/cli/args.hpp"

namespace postmortem::cli {

// Top-level help: the spec §5 command table plus the global flags.
[[nodiscard]] std::string general_usage();

// Help for one subcommand. Falls back to general_usage() for Command::None.
[[nodiscard]] std::string command_usage(Command c);

// One-line reminder printed after a usage error.
[[nodiscard]] std::string usage_hint();

}  // namespace postmortem::cli
