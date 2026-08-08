#pragma once

#include "core/cli/args.hpp"
#include "core/text/table.hpp"

namespace postmortem::commands {

// `pm timeline` - merged, multi-provider crash timeline.
[[nodiscard]] int run_timeline(const cli::CommandLine& cmdline, const text::Style& style);

// `pm analyze` - trend analysis and an evidence-weighted verdict.
[[nodiscard]] int run_analyze(const cli::CommandLine& cmdline, const text::Style& style);

}  // namespace postmortem::commands
