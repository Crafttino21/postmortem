// pm - postmortem's command-line entry point.
//
// Responsibilities kept deliberately small: refuse unsupported hosts, parse the
// command line, set up the console, dispatch. Everything else lives in
// commands/ so that each milestone adds a file rather than a branch here.

#include <cstdio>
#include <string>
#include <vector>

#include "commands/decode.hpp"
#include "commands/mitigate.hpp"
#include "commands/report.hpp"
#include "commands/scan.hpp"
#include "commands/status.hpp"
#include "commands/timeline.hpp"
#include "commands/topology.hpp"
#include "commands/watch.hpp"
#include "core/cli/args.hpp"
#include "core/cli/usage.hpp"
#include "core/text/table.hpp"
#include "core/version.hpp"
#include "platform/arch.hpp"
#include "platform/console.hpp"

namespace {

namespace exit_code {
constexpr int kSuccess = 0;
constexpr int kFailure = 1;          // the command ran and could not finish
constexpr int kUsage = 2;            // bad command line
constexpr int kUnsupportedHost = 3;  // wrong architecture (spec §3)
}  // namespace exit_code

void write(FILE* stream, const std::string& text) {
    std::fwrite(text.data(), 1, text.size(), stream);
}

void write_error(const std::string& message) {
    write(stderr, "pm: " + message + "\n");
}

int report_unimplemented(const postmortem::cli::CommandLine& cmdline) {
    const int milestone = postmortem::cli::implementing_milestone(cmdline.command);
    write_error("'" + cmdline.command_name +
                "' is not implemented in this build; it arrives with spec section 8 milestone " +
                std::to_string(milestone));
    write(stderr,
          "This build implements 'status' and 'decode'. Run 'pm --help' for the full "
          "command list.\n");
    return exit_code::kFailure;
}

}  // namespace

int main() {
    using namespace postmortem;

    const std::vector<std::string> arguments = platform::command_line_arguments();
    const cli::ParseResult parsed = cli::parse(arguments);

    if (!parsed.ok) {
        write_error(parsed.error);
        write(stderr, cli::usage_hint());
        return exit_code::kUsage;
    }

    const cli::CommandLine& cmdline = parsed.cmdline;

    if (cmdline.version) {
        write(stdout, std::string("postmortem ") + kVersion + "\n");
        return exit_code::kSuccess;
    }

    if (cmdline.help) {
        write(stdout, cli::command_usage(cmdline.command));
        return exit_code::kSuccess;
    }

    if (cmdline.command == cli::Command::None) {
        write(stdout, cli::general_usage());
        return exit_code::kSuccess;
    }

    // Checked after help/version so that `pm --help` still works on a machine
    // this build cannot analyse.
    if (const auto problem = platform::unsupported_host_architecture()) {
        write_error(*problem);
        return exit_code::kUnsupportedHost;
    }

    const bool color = platform::prepare_console(cmdline.global.no_color);
    const text::Style style = color ? text::Style::ansi() : text::Style::plain();

    switch (cmdline.command) {
        case cli::Command::Status:
            if (!cmdline.operands.empty()) {
                write_error("'status' takes no arguments, but got '" + cmdline.operands.front() +
                            "'");
                return exit_code::kUsage;
            }
            return commands::run_status(cmdline, style);

        case cli::Command::Decode:
            return commands::run_decode(cmdline, style);

        case cli::Command::Scan:
            return commands::run_scan(cmdline, style);

        case cli::Command::Show:
            return commands::run_show(cmdline, style);

        case cli::Command::Topology:
            return commands::run_topology(cmdline, style);

        case cli::Command::Timeline:
            return commands::run_timeline(cmdline, style);

        case cli::Command::Analyze:
            return commands::run_analyze(cmdline, style);

        case cli::Command::Watch:
            return commands::run_watch(cmdline, style);

        case cli::Command::Mitigate:
            return commands::run_mitigate(cmdline, style);

        case cli::Command::Report:
            return commands::run_report(cmdline, style);

        case cli::Command::None:
            break;
    }

    write(stdout, cli::general_usage());
    return exit_code::kSuccess;
}
