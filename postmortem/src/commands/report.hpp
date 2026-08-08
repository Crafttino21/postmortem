#pragma once

#include "core/cli/args.hpp"
#include "core/text/table.hpp"

namespace postmortem::commands {

// `pm report [--format json|md] [--redact]` - export.
[[nodiscard]] int run_report(const cli::CommandLine& cmdline, const text::Style& style);

}  // namespace postmortem::commands
