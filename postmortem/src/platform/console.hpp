#pragma once

#include <string>
#include <vector>

namespace postmortem::platform {

// Puts the console into UTF-8 mode and enables VT sequence processing.
// Returns true if ANSI colour should be used, honouring, in order:
//   1. the --no-color flag,
//   2. the NO_COLOR environment variable (no-color.org),
//   3. whether stdout is actually a console rather than a pipe or file,
//   4. whether the console accepted ENABLE_VIRTUAL_TERMINAL_PROCESSING.
[[nodiscard]] bool prepare_console(bool no_color_flag);

// The process command line as UTF-8, excluding the program name.
//
// The narrow argv main() receives is encoded in the active ANSI code page and
// mangles non-ASCII paths - which matters because --evtx takes a path the user
// may well have exported to a directory with an umlaut in it.
[[nodiscard]] std::vector<std::string> command_line_arguments();

}  // namespace postmortem::platform
