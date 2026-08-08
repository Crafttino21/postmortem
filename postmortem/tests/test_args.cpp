#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include "check.hpp"
#include "core/cli/args.hpp"

using postmortem::cli::Command;
using postmortem::cli::ParseResult;

namespace {

ParseResult parse(std::vector<std::string> arguments) {
    return postmortem::cli::parse(arguments);
}

}  // namespace

PM_TEST(args_bare_invocation_selects_no_command) {
    const ParseResult result = parse({});
    PM_CHECK(result.ok);
    PM_CHECK_EQ(result.cmdline.command, Command::None);
    PM_CHECK(!result.cmdline.help);
}

PM_TEST(args_recognises_every_command_in_the_spec) {
    const std::vector<std::pair<std::string, Command>> expected{
        {"status", Command::Status},     {"scan", Command::Scan},
        {"show", Command::Show},         {"timeline", Command::Timeline},
        {"analyze", Command::Analyze},   {"watch", Command::Watch},
        {"decode", Command::Decode},     {"topology", Command::Topology},
        {"mitigate", Command::Mitigate}, {"report", Command::Report},
    };

    for (const auto& [name, command] : expected) {
        const ParseResult result = parse({name});
        PM_CHECK(result.ok);
        PM_CHECK_EQ(result.cmdline.command, command);
        PM_CHECK_EQ(result.cmdline.command_name, name);
    }
}

PM_TEST(args_global_flags_are_accepted_on_either_side_of_the_command) {
    const ParseResult before = parse({"--json", "--verbose", "status"});
    PM_CHECK(before.ok);
    PM_CHECK_EQ(before.cmdline.command, Command::Status);
    PM_CHECK(before.cmdline.global.json);
    PM_CHECK(before.cmdline.global.verbose);

    const ParseResult after = parse({"status", "--json", "--verbose"});
    PM_CHECK(after.ok);
    PM_CHECK_EQ(after.cmdline.command, Command::Status);
    PM_CHECK(after.cmdline.global.json);
    PM_CHECK(after.cmdline.global.verbose);
}

PM_TEST(args_parses_all_global_flags) {
    const ParseResult result =
        parse({"scan", "--json", "--no-color", "--verbose", "--yes", "--evtx", "C:\\logs\\sys.evtx"});
    PM_CHECK(result.ok);
    PM_CHECK(result.cmdline.global.json);
    PM_CHECK(result.cmdline.global.no_color);
    PM_CHECK(result.cmdline.global.verbose);
    PM_CHECK(result.cmdline.global.yes);
    PM_CHECK(result.cmdline.global.evtx.has_value());
    PM_CHECK_EQ(*result.cmdline.global.evtx, std::string("C:\\logs\\sys.evtx"));
}

PM_TEST(args_accepts_both_option_value_spellings) {
    const ParseResult separated = parse({"scan", "--since", "90d"});
    PM_CHECK(separated.ok);
    PM_CHECK(separated.cmdline.has_option("since"));
    PM_CHECK_EQ(*separated.cmdline.option("since"), std::string("90d"));

    const ParseResult joined = parse({"scan", "--since=90d"});
    PM_CHECK(joined.ok);
    PM_CHECK_EQ(*joined.cmdline.option("since"), std::string("90d"));
}

PM_TEST(args_repeated_option_takes_the_last_value) {
    const ParseResult result = parse({"report", "--format", "json", "--format", "md"});
    PM_CHECK(result.ok);
    PM_CHECK_EQ(*result.cmdline.option("format"), std::string("md"));
}

PM_TEST(args_collects_positional_operands) {
    const ParseResult show = parse({"show", "3"});
    PM_CHECK(show.ok);
    PM_CHECK_EQ(show.cmdline.operands.size(), std::size_t{1});
    PM_CHECK_EQ(show.cmdline.operands.front(), std::string("3"));

    const ParseResult mitigate = parse({"mitigate", "apply", "max-cpu-99", "--scheme", "all"});
    PM_CHECK(mitigate.ok);
    PM_CHECK_EQ(mitigate.cmdline.operands.size(), std::size_t{2});
    PM_CHECK_EQ(mitigate.cmdline.operands[0], std::string("apply"));
    PM_CHECK_EQ(mitigate.cmdline.operands[1], std::string("max-cpu-99"));
    PM_CHECK_EQ(*mitigate.cmdline.option("scheme"), std::string("all"));
}

PM_TEST(args_decode_takes_register_values) {
    const ParseResult result =
        parse({"decode", "--mci-stat", "0xbea0000000000108", "--mci-addr", "0x1fff800c062b2a9"});
    PM_CHECK(result.ok);
    PM_CHECK_EQ(*result.cmdline.option("mci-stat"), std::string("0xbea0000000000108"));
    PM_CHECK_EQ(*result.cmdline.option("mci-addr"), std::string("0x1fff800c062b2a9"));
}

PM_TEST(args_double_dash_stops_option_parsing) {
    const ParseResult result = parse({"show", "--", "--not-an-option"});
    PM_CHECK(result.ok);
    PM_CHECK_EQ(result.cmdline.operands.size(), std::size_t{1});
    PM_CHECK_EQ(result.cmdline.operands.front(), std::string("--not-an-option"));
}

PM_TEST(args_help_and_version) {
    PM_CHECK(parse({"--help"}).cmdline.help);
    PM_CHECK(parse({"-h"}).cmdline.help);
    PM_CHECK(parse({"-?"}).cmdline.help);
    PM_CHECK(parse({"--version"}).cmdline.version);

    // --help after a command asks for that command's help, so the command must
    // survive parsing.
    const ParseResult scoped = parse({"decode", "--help"});
    PM_CHECK(scoped.ok);
    PM_CHECK(scoped.cmdline.help);
    PM_CHECK_EQ(scoped.cmdline.command, Command::Decode);
}

PM_TEST(args_rejects_unknown_command) {
    const ParseResult result = parse({"stats"});
    PM_CHECK(!result.ok);
    PM_CHECK(result.error.find("unknown command") != std::string::npos);
    PM_CHECK(result.error.find("stats") != std::string::npos);
}

PM_TEST(args_rejects_unknown_option) {
    const ParseResult result = parse({"status", "--colour"});
    PM_CHECK(!result.ok);
    PM_CHECK(result.error.find("unknown option") != std::string::npos);
}

PM_TEST(args_rejects_option_belonging_to_another_command) {
    // `scan` owns --since, so `status --since` is a mistake worth naming
    // precisely rather than reporting as a generic unknown option. Reordering
    // would not help here, so the message must not suggest it.
    const ParseResult result = parse({"status", "--since", "90d"});
    PM_CHECK(!result.ok);
    PM_CHECK(result.error.find("scan") != std::string::npos);
    PM_CHECK(result.error.find("subcommand first") == std::string::npos);
}

PM_TEST(args_option_before_its_command_is_diagnosed) {
    // Here reordering *is* the fix, so say so.
    const ParseResult result = parse({"--since", "90d", "scan"});
    PM_CHECK(!result.ok);
    PM_CHECK(result.error.find("subcommand first") != std::string::npos);
}

PM_TEST(args_rejects_missing_option_value) {
    const ParseResult result = parse({"scan", "--since"});
    PM_CHECK(!result.ok);
    PM_CHECK(result.error.find("requires a value") != std::string::npos);
}

PM_TEST(args_rejects_value_on_a_flag) {
    const ParseResult result = parse({"status", "--json=yes"});
    PM_CHECK(!result.ok);
    PM_CHECK(result.error.find("does not take a value") != std::string::npos);
}

PM_TEST(args_rejects_unknown_short_option) {
    const ParseResult result = parse({"status", "-j"});
    PM_CHECK(!result.ok);
    PM_CHECK(result.error.find("long options only") != std::string::npos);
}

PM_TEST(args_milestone_metadata_matches_the_build_order) {
    // The milestone numbers come straight from spec §8 and do not change as
    // commands land; asserting *which* are implemented would make this test
    // churn on every milestone, so it checks the stable facts instead.
    const std::vector<std::pair<Command, int>> build_order{
        {Command::Status, 1},   {Command::Decode, 3},   {Command::Scan, 4},
        {Command::Show, 4},     {Command::Topology, 5}, {Command::Timeline, 6},
        {Command::Analyze, 7},  {Command::Mitigate, 8}, {Command::Watch, 9},
        {Command::Report, 10},
    };
    for (const auto& [command, milestone] : build_order) {
        PM_CHECK_EQ(postmortem::cli::implementing_milestone(command), milestone);
        PM_CHECK(!postmortem::cli::command_name(command).empty());
    }

    // Whatever else is true, milestone 1 has shipped and Command::None is not
    // a command.
    PM_CHECK(postmortem::cli::is_implemented(Command::Status));
    PM_CHECK(postmortem::cli::command_name(Command::None).empty());
    PM_CHECK_EQ(postmortem::cli::implementing_milestone(Command::None), 0);
}
