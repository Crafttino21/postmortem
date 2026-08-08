#include "core/cli/usage.hpp"

namespace postmortem::cli {

std::string general_usage() {
    return
        "pm - postmortem: Unoffical AMD Ryzen Zen3 Debugging Tool\n"
        "\n"
        "Usage:\n"
        "  pm <command> [options]\n"
        "\n"
        "Commands:\n"
        "  status                          System snapshot\n"
        "  scan [--since 90d] [--evtx F]   Decode all WHEA records\n"
        "  show <n>                        Full decode of one incident, all sections\n"
        "  timeline [--since 90d]          Merged crash timeline\n"
        "  analyze                         Trend analysis + evidence-weighted verdict\n"
        "  watch [--log F] [--exec CMD]    Live subscription\n"
        "  decode --cper <hex|@file>       Decode a CPER blob standalone\n"
        "  decode --mci-stat 0xbea...      Decode a single MCA register value\n"
        "  topology                        APIC -> core/thread/CCD map\n"
        "  mitigate list|apply|revert <n>  Mitigation control\n"
        "  report [--format json|md]       Export\n"
        "\n"
        "Global options:\n"
        "  --json           Machine-readable output\n"
        "  --no-color       Disable ANSI colour (NO_COLOR is honoured too)\n"
        "  --verbose        Additional detail and diagnostics\n"
        "  --yes            Assume yes for confirmation prompts\n"
        "  --evtx <path>    Read from a saved .evtx file instead of the live log\n"
        "  --help, -h       Show this help, or help for a command\n"
        "  --version        Show the version\n"
        "\n"
        "Commands not yet implemented are accepted by the parser and report which\n"
        "milestone delivers them.\n";
}

std::string command_usage(Command c) {
    switch (c) {
        case Command::Status:
            return
                "pm status - snapshot of the machine's crash-forensics state\n"
                "\n"
                "Usage:\n"
                "  pm status [--json] [--no-color] [--verbose]\n"
                "\n"
                "Reports CPU identity and topology counts, BIOS/board firmware from SMBIOS,\n"
                "and OS build, install date and boot time.\n"
                "\n"
                "Crash-dump configuration, power/idle state, virtualization and DIMM\n"
                "population (spec §4.8) arrive with later milestones.\n";
        case Command::Scan:
            return
                "pm scan - decode every WHEA record in the log\n"
                "\n"
                "Usage:\n"
                "  pm scan [--since 90d] [--evtx <path>] [--json]\n"
                "\n"
                "An uncorrectable machine check is broadcast to every core, so one fault\n"
                "writes one record per processor. Those are collapsed into a single incident\n"
                "with N reporting cores rather than listed N times.\n"
                "\n"
                "Records timestamped shortly after a boot are flagged: MCA banks survive a\n"
                "warm reset, so Windows harvests them on the way up and they describe the\n"
                "crash that ended the *previous* session.\n";
        case Command::Show:
            return
                "pm show - full decode of one incident, all CPER sections\n"
                "\n"
                "Usage:\n"
                "  pm show <n> [--since 90d] [--evtx <path>] [--json] [--verbose]\n"
                "\n"
                "<n> is the incident number from 'pm scan', starting at 1. --verbose adds the\n"
                "raw hex of every CPER section and the original event XML.\n";
        case Command::Timeline:
            return
                "pm timeline - merged, multi-provider crash timeline\n"
                "\n"
                "Usage:\n"
                "  pm timeline [--since 90d] [--evtx <path>] [--json]\n";
        case Command::Analyze:
            return
                "pm analyze - trend analysis and an evidence-weighted verdict\n"
                "\n"
                "Usage:\n"
                "  pm analyze [--evtx <path>] [--json]\n";
        case Command::Watch:
            return
                "pm watch - live subscription to incoming WHEA events\n"
                "\n"
                "Usage:\n"
                "  pm watch [--log <path>] [--exec <command>]\n";
        case Command::Decode:
            return
                "pm decode - decode a blob or register value with no access to the machine\n"
                "\n"
                "Usage:\n"
                "  pm decode --cper <hex|base64|@file>\n"
                "  pm decode --mci-stat <value> [--mci-addr <value>] [--mci-misc <value>]\n"
                "\n"
                "Options:\n"
                "  --cper <value>     A CPER record as hex or base64, or @path to read a file.\n"
                "                     Whitespace, 0x prefixes and commas are ignored, so text\n"
                "                     pasted straight out of Event Viewer works.\n"
                "  --mci-stat <v>     MCA_STATUS. 0x.. is hex, 0b.. binary, plain digits are\n"
                "                     decimal (what Event Viewer's friendly view shows).\n"
                "  --mci-addr <v>     MCA_ADDR.\n"
                "  --mci-misc <v>     MCA_MISC.\n"
                "  --vendor <name>    amd, intel or unknown. Decides how MCA_ADDR and the\n"
                "                     vendor-specific status bits are read. Defaults to\n"
                "                     unknown, which assumes the AMD SMCA layout and says so.\n"
                "\n"
                "Examples:\n"
                "  pm decode --mci-stat 0xbea0000000000108 --mci-addr 0x1fff800c062b2a9 \\\n"
                "            --vendor amd\n"
                "  pm decode --cper @record.bin --verbose\n";
        case Command::Topology:
            return
                "pm topology - APIC ID to core/thread/CCD map\n"
                "\n"
                "Usage:\n"
                "  pm topology [--json]\n";
        case Command::Mitigate:
            return
                "pm mitigate - inspect, apply and revert named mitigations\n"
                "\n"
                "Usage:\n"
                "  pm mitigate list\n"
                "  pm mitigate apply <name> [--scheme all|<guid>] [--yes]\n"
                "  pm mitigate revert <name> [--scheme all|<guid>] [--yes]\n";
        case Command::Report:
            return
                "pm report - export a full structured or human-readable report\n"
                "\n"
                "Usage:\n"
                "  pm report [--format json|md] [--redact]\n";
        case Command::None:
            break;
    }
    return general_usage();
}

std::string usage_hint() {
    return "Run 'pm --help' for usage.\n";
}

}  // namespace postmortem::cli
