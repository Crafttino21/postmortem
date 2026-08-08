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
        "  live [--interval 1s]            Live view of what the CPU is doing\n"
        "  live --stacks                   Live sampled call stacks (elevated)\n"
        "  watch-mem --pid P --at ADDR     Live byte view of a process's memory\n"
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
                "  pm scan --records                 every raw record, one row each\n"
                "  pm scan --group-by event,bank,apic  frequency tally, most frequent first\n"
                "\n"
                "Group fields: apic, bank, event, type, transaction, status, code, address,\n"
                "page, class, severity, day, hour. Combine them with commas.\n"
                "\n"
                "  pm scan --group-by status         which MCA_STATUS values recur\n"
                "  pm scan --group-by page           whether addresses cluster in one page\n"
                "  pm scan --group-by hour           time-of-day pattern\n"
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
                "  --walk             Step through the record field by field, showing each\n"
                "                     byte offset as it is consumed and what it decodes to.\n"
                "                     Interactive when stdout is a console; a full listing\n"
                "                     when redirected.\n"
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
        case Command::Live:
            return
                "pm live - watch what the CPU is doing, until you stop it\n"
                "\n"
                "Usage:\n"
                "  pm live [--interval 1s] [--no-etw]\n"
                "\n"
                "Shows, per logical processor and refreshing on a timer: actual frequency,\n"
                "performance relative to nominal, load, idle-state (C1/C2/C3) residency,\n"
                "parking, and interrupt and DPC rates. Any WHEA record that arrives while\n"
                "watching appears in the feed at the bottom immediately.\n"
                "\n"
                "Run elevated and it additionally starts an ETW kernel session, adding real\n"
                "context-switch, interrupt and DPC counts per core rather than sampled rates.\n"
                "--no-etw skips that even when elevated.\n"
                "\n"
                "Keys:  q quit   space pause   s sort by load   r reset the feed\n"
                "\n"
                "What it cannot show: the executed instruction stream, register contents or\n"
                "bus traffic. Those need Intel PT / AMD IBS or MSR access, which means a\n"
                "kernel driver, which this tool does not use (spec section 2). Everything\n"
                "here comes from documented user-mode APIs.\n";
        case Command::WatchMem:
            return
                "pm watch-mem - watch a region of another process's memory change\n"
                "\n"
                "Usage:\n"
                "  pm watch-mem --pid <id|name> --regions\n"
                "  pm watch-mem --pid <id|name> --at <address> [--len 256]\n"
                "  pm watch-mem --pid <id|name> --module <name> [--offset <n>]\n"
                "\n"
                "Options:\n"
                "  --pid <id|name>   Process id, or an executable name if it is unambiguous.\n"
                "  --regions         List the committed regions, so you can pick an address.\n"
                "  --at <address>    Where to start reading. 0x.. is hex.\n"
                "  --module <name>   Start at a loaded module's base instead, plus --offset.\n"
                "  --len <n>         How many bytes, up to 4096. Default 256.\n"
                "  --interval <d>    Refresh period. Default 1s, minimum 50ms.\n"
                "\n"
                "Bytes that changed since the last tick are shown in red, ones that changed\n"
                "earlier in yellow, and unreadable bytes as ??. Keys: q quit, space pause,\n"
                "r reset the change history.\n"
                "\n"
                "The target is never suspended and nothing is ever written to it. Because it\n"
                "keeps running while being read, a multi-byte value can be caught mid-write\n"
                "and read torn. Kernel memory is not reachable from user mode at all.\n";
        case Command::None:
            break;
    }
    return general_usage();
}

std::string usage_hint() {
    return "Run 'pm --help' for usage.\n";
}

}  // namespace postmortem::cli
