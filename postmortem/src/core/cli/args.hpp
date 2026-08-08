// Command-line parsing for pm (spec §5).
//
// Deliberately free of Windows headers so it can be unit-tested on any
// platform - see tests/test_args.cpp. main.cpp converts the native wide
// command line to UTF-8 and hands the tail to parse().

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace postmortem::cli {

// The subcommand surface from spec §5. Commands parse in milestone 1 even when
// their implementation lands later; an unimplemented command is reported as
// such rather than as a parse error.
enum class Command {
    None,       // nothing given, or only global flags
    Status,
    Scan,
    Show,
    Timeline,
    Analyze,
    Watch,
    Decode,
    Topology,
    Mitigate,
    Report,
    Live,      // not in spec §5; added on request
    WatchMem,  // not in spec §5; added on request
};

// Spec §5: global flags, accepted before or after the subcommand.
struct GlobalOptions {
    bool json = false;
    bool no_color = false;
    bool verbose = false;
    bool yes = false;
    std::optional<std::string> evtx;
};

// A subcommand-specific option, e.g. "--since 90d" -> {"since", "90d"}.
// Flags without a value carry an empty string.
struct Option {
    std::string name;
    std::string value;
};

struct CommandLine {
    Command command = Command::None;
    std::string command_name;           // as typed, for diagnostics
    GlobalOptions global;
    std::vector<Option> options;        // subcommand-specific
    std::vector<std::string> operands;  // positional arguments
    bool help = false;                  // --help / -h / -?
    bool version = false;               // --version

    // Last occurrence wins, so a repeated option overrides rather than errors.
    [[nodiscard]] const std::string* option(std::string_view name) const;
    [[nodiscard]] bool has_option(std::string_view name) const;
};

struct ParseResult {
    bool ok = false;
    CommandLine cmdline;
    std::string error;  // human-readable; set only when ok == false
};

// argv_tail excludes the program name.
ParseResult parse(const std::vector<std::string>& argv_tail);

// Canonical spelling of a command, "" for Command::None.
[[nodiscard]] std::string_view command_name(Command c);

// True once the command's implementation exists. Milestone 1 ships `status`
// only; the rest parse and report the milestone that will deliver them.
[[nodiscard]] bool is_implemented(Command c);

// Spec §8 milestone that delivers a command, for the not-yet-implemented
// message. Returns 0 for Command::None.
[[nodiscard]] int implementing_milestone(Command c);

}  // namespace postmortem::cli
