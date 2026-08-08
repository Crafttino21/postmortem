#include "core/cli/args.hpp"

#include <algorithm>
#include <array>
#include <span>

namespace postmortem::cli {
namespace {

struct OptionSpec {
    std::string_view name;
    bool takes_value;
};

// Spec §5 global flags, plus the two conventional extras.
constexpr std::array<OptionSpec, 7> kGlobalOptions{{
    {"json", false},
    {"no-color", false},
    {"verbose", false},
    {"yes", false},
    {"evtx", true},
    {"help", false},
    {"version", false},
}};

// Per-subcommand options. `--evtx` is global (spec §5) even though `scan`
// advertises it, so it is not repeated here.
constexpr std::array<OptionSpec, 1> kScanOptions{{{"since", true}}};
constexpr std::array<OptionSpec, 1> kTimelineOptions{{{"since", true}}};
constexpr std::array<OptionSpec, 2> kWatchOptions{{{"log", true}, {"exec", true}}};
// §5 names --cper and --mci-stat. MciAddr/MciMisc are decoded alongside
// MciStat (§4.3) and the §7 test vectors pair stat with addr, so the register
// decoder accepts all three registers as separate operands.
// --vendor is not in §5's list, but MCA_ADDR and MCA_STATUS[56:53] are read
// differently on AMD and Intel (§4.3) and a pasted register value carries no
// hint of which. Without it the decoder assumes SMCA and says so.
constexpr std::array<OptionSpec, 5> kDecodeOptions{{
    {"cper", true},
    {"mci-stat", true},
    {"mci-addr", true},
    {"mci-misc", true},
    {"vendor", true},
}};
constexpr std::array<OptionSpec, 1> kMitigateOptions{{{"scheme", true}}};
// `report` builds on the same event query as scan and timeline, so it accepts
// --since too rather than silently always covering the whole log.
constexpr std::array<OptionSpec, 3> kReportOptions{{
    {"format", true},
    {"redact", false},
    {"since", true},
}};

struct CommandSpec {
    std::string_view name;
    Command command;
    int milestone;   // spec §8 build order
    bool implemented;
    std::span<const OptionSpec> options;
};

constexpr std::array<CommandSpec, 10> kCommands{{
    {"status",   Command::Status,   1, true,  {}},
    {"scan",     Command::Scan,     4, true,  kScanOptions},
    {"show",     Command::Show,     4, true,  kScanOptions},
    {"timeline", Command::Timeline, 6, true,  kTimelineOptions},
    {"analyze",  Command::Analyze,  7, true,  kTimelineOptions},
    {"watch",    Command::Watch,    9, true,  kWatchOptions},
    {"decode",   Command::Decode,   3, true,  kDecodeOptions},
    {"topology", Command::Topology, 5, true,  {}},
    {"mitigate", Command::Mitigate, 8, true,  kMitigateOptions},
    {"report",   Command::Report,  10, true,  kReportOptions},
}};

const CommandSpec* find_command(std::string_view name) {
    for (const auto& spec : kCommands) {
        if (spec.name == name) return &spec;
    }
    return nullptr;
}

const CommandSpec* find_command(Command c) {
    for (const auto& spec : kCommands) {
        if (spec.command == c) return &spec;
    }
    return nullptr;
}

const OptionSpec* find_option(std::span<const OptionSpec> options, std::string_view name) {
    for (const auto& opt : options) {
        if (opt.name == name) return &opt;
    }
    return nullptr;
}

// Which subcommand, if any, owns an option name. Used to turn "unknown option"
// into "you put it before the subcommand".
std::string_view owning_command(std::string_view option_name) {
    for (const auto& spec : kCommands) {
        if (find_option(spec.options, option_name) != nullptr) return spec.name;
    }
    return {};
}

ParseResult fail(std::string error) {
    ParseResult result;
    result.ok = false;
    result.error = std::move(error);
    return result;
}

std::string quote(std::string_view s) {
    std::string out = "'";
    out.append(s);
    out.push_back('\'');
    return out;
}

}  // namespace

const std::string* CommandLine::option(std::string_view name) const {
    const std::string* found = nullptr;
    for (const auto& opt : options) {
        if (opt.name == name) found = &opt.value;  // last occurrence wins
    }
    return found;
}

bool CommandLine::has_option(std::string_view name) const {
    return option(name) != nullptr;
}

std::string_view command_name(Command c) {
    const CommandSpec* spec = find_command(c);
    return spec != nullptr ? spec->name : std::string_view{};
}

bool is_implemented(Command c) {
    const CommandSpec* spec = find_command(c);
    return spec != nullptr && spec->implemented;
}

int implementing_milestone(Command c) {
    const CommandSpec* spec = find_command(c);
    return spec != nullptr ? spec->milestone : 0;
}

ParseResult parse(const std::vector<std::string>& argv_tail) {
    CommandLine cmdline;
    const CommandSpec* active = nullptr;
    bool options_terminated = false;   // seen "--"

    for (std::size_t i = 0; i < argv_tail.size(); ++i) {
        const std::string& token = argv_tail[i];

        if (!options_terminated && token == "--") {
            options_terminated = true;
            continue;
        }

        const bool is_long_option =
            !options_terminated && token.size() > 2 && token.rfind("--", 0) == 0;
        const bool is_short_option =
            !options_terminated && token.size() > 1 && token[0] == '-' && token[1] != '-';

        if (is_long_option) {
            std::string name = token.substr(2);
            std::optional<std::string> inline_value;
            if (const auto eq = name.find('='); eq != std::string::npos) {
                inline_value = name.substr(eq + 1);
                name.erase(eq);
            }
            if (name.empty()) {
                return fail("malformed option " + quote(token));
            }

            const OptionSpec* spec = nullptr;
            bool is_global = false;
            if (active != nullptr) spec = find_option(active->options, name);
            if (spec == nullptr) {
                spec = find_option(kGlobalOptions, name);
                is_global = spec != nullptr;
            }

            if (spec == nullptr) {
                std::string message = "unknown option " + quote("--" + name);
                if (active != nullptr) {
                    message += " for command " + quote(active->name);
                }
                if (const std::string_view owner = owning_command(name); !owner.empty()) {
                    message += "; it belongs to " + quote(owner);
                    // Distinguish "wrong subcommand" from "no subcommand yet":
                    // only the latter is fixed by reordering.
                    if (active == nullptr) {
                        message += " - put the subcommand first, e.g. pm ";
                        message.append(owner);
                        message += " --";
                        message += name;
                    }
                }
                return fail(std::move(message));
            }

            std::string value;
            if (spec->takes_value) {
                if (inline_value.has_value()) {
                    value = *inline_value;
                } else if (i + 1 < argv_tail.size()) {
                    value = argv_tail[++i];
                } else {
                    return fail("option " + quote("--" + name) + " requires a value");
                }
            } else if (inline_value.has_value()) {
                return fail("option " + quote("--" + name) + " does not take a value");
            }

            if (is_global) {
                if (name == "json") {
                    cmdline.global.json = true;
                } else if (name == "no-color") {
                    cmdline.global.no_color = true;
                } else if (name == "verbose") {
                    cmdline.global.verbose = true;
                } else if (name == "yes") {
                    cmdline.global.yes = true;
                } else if (name == "evtx") {
                    cmdline.global.evtx = value;
                } else if (name == "help") {
                    cmdline.help = true;
                } else if (name == "version") {
                    cmdline.version = true;
                }
            } else {
                cmdline.options.push_back({std::move(name), std::move(value)});
            }
            continue;
        }

        if (is_short_option) {
            // Spec §5 defines no short flags; only the universal help aliases
            // are accepted, so that a typo'd short form is a clear error rather
            // than a silently ignored argument.
            if (token == "-h" || token == "-?") {
                cmdline.help = true;
                continue;
            }
            return fail("unknown option " + quote(token) +
                        "; postmortem uses long options only (e.g. --verbose)");
        }

        if (active == nullptr && cmdline.command == Command::None) {
            const CommandSpec* spec = find_command(token);
            if (spec == nullptr) {
                return fail("unknown command " + quote(token) + "; run 'pm --help' for the list");
            }
            active = spec;
            cmdline.command = spec->command;
            cmdline.command_name = token;
            continue;
        }

        cmdline.operands.push_back(token);
    }

    ParseResult result;
    result.ok = true;
    result.cmdline = std::move(cmdline);
    return result;
}

}  // namespace postmortem::cli
