#pragma once

#include "core/cli/args.hpp"
#include "core/text/table.hpp"

namespace postmortem::commands {

// `pm scan` - every WHEA record in the range, collapsed into incidents.
[[nodiscard]] int run_scan(const cli::CommandLine& cmdline, const text::Style& style);

// `pm show <n>` - the full decode of one incident, all sections.
[[nodiscard]] int run_show(const cli::CommandLine& cmdline, const text::Style& style);

}  // namespace postmortem::commands
