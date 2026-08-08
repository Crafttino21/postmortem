#pragma once

#include "core/cli/args.hpp"
#include "core/text/table.hpp"

namespace postmortem::commands {

// `pm decode` (spec §5, §8 milestone 3).
//
// Decodes a CPER blob or MCA register values that were pasted from somewhere
// else. Spec §5: "`decode` operating on a value pasted from someone else's
// event log - with no access to that machine - must work. That is a core use
// case, not an extra." Nothing in here touches the local machine except to
// read a file the user named.
[[nodiscard]] int run_decode(const cli::CommandLine& cmdline, const text::Style& style);

}  // namespace postmortem::commands
