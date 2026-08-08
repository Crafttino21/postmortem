#pragma once

#include <windows.h>

#include "core/cli/args.hpp"
#include "core/text/table.hpp"

namespace postmortem::commands {

// `pm watch` - live push subscription, decoded and printed as records arrive.
[[nodiscard]] int run_watch(const cli::CommandLine& cmdline, const text::Style& style);

}  // namespace postmortem::commands
