// `pm mitigate` (spec §4.9).

#include "commands/mitigate.hpp"

#include <chrono>
#include <cstdio>
#include <map>

#include "commands/common.hpp"
#include "core/json/reader.hpp"
#include "core/json/writer.hpp"
#include "core/text/format.hpp"
#include "platform/eventlog.hpp"
#include "platform/power.hpp"
#include "platform/registry.hpp"
#include "platform/state.hpp"
#include "platform/strings.hpp"

namespace postmortem::commands {
namespace {

using platform::power_settings::kIdleDisable;
using platform::power_settings::kIdleDemoteThreshold;
using platform::power_settings::kIdlePromoteThreshold;
using platform::power_settings::kProcThrottleMaximum;
using platform::power_settings::kProcThrottleMinimum;

constexpr const wchar_t* kCrashControlKey = L"SYSTEM\\CurrentControlSet\\Control\\CrashControl";

enum class Kind {
    PowerSetting,
    CrashControl,
};

struct Mitigation {
    const char* name;
    Kind kind;
    const char* setting_guid;      // PowerSetting only
    const char* description;
    const char* cost;
    std::uint32_t target_ac;
    std::uint32_t target_dc;
};

// Spec §4.9's table, verbatim.
const std::vector<Mitigation>& mitigations() {
    static const std::vector<Mitigation> list{
        {"max-cpu-99", Kind::PowerSetting, kProcThrottleMaximum,
         "Caps the maximum processor state at 99%, which disables boost states.",
         "Loses peak single-core clocks; typically a few percent of performance.", 99, 99},
        {"min-cpu-100", Kind::PowerSetting, kProcThrottleMinimum,
         "Holds the minimum processor state at 100%, keeping cores out of deep idle.",
         "Raises idle power draw and idle temperatures noticeably.", 100, 100},
        {"idle-disable", Kind::PowerSetting, kIdleDisable,
         "Disables processor idle states entirely.",
         "Raises idle power draw substantially; the largest cost of the six.", 1, 1},
        {"idle-promote", Kind::PowerSetting, kIdlePromoteThreshold,
         "Raises the idle promote threshold so cores enter deeper idle states less eagerly.",
         "Small increase in idle power draw.", 100, 100},
        {"dumps-on", Kind::CrashControl, nullptr,
         "Enables a kernel memory dump and stops the automatic reboot, so a bugcheck leaves "
         "evidence and stays on screen.",
         "Needs pagefile space on the system volume; the machine stops rebooting by itself.",
         1, 1},
        {"nmi-dump", Kind::CrashControl, nullptr,
         "Enables crash-on-NMI and Ctrl+Scroll-Lock, so a hung machine can be forced to "
         "bugcheck and produce a dump.",
         "None in normal use; Ctrl+Scroll-Lock twice will deliberately crash the machine.",
         1, 1},
    };
    return list;
}

const Mitigation* find_mitigation(std::string_view name) {
    for (const Mitigation& mitigation : mitigations()) {
        if (name == mitigation.name) return &mitigation;
    }
    return nullptr;
}

std::int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// --- Current state ---------------------------------------------------------

struct CrashControlState {
    bool readable = false;
    std::optional<std::uint32_t> crash_dump_enabled;
    std::optional<std::uint32_t> auto_reboot;
    std::optional<std::uint32_t> nmi_crash_dump;
    std::optional<std::uint32_t> crash_on_ctrl_scroll;
    std::string dump_file;
};

CrashControlState read_crash_control() {
    using platform::registry::Hive;
    CrashControlState state;

    state.crash_dump_enabled =
        platform::registry::read_dword(Hive::LocalMachine, kCrashControlKey, L"CrashDumpEnabled");
    state.auto_reboot =
        platform::registry::read_dword(Hive::LocalMachine, kCrashControlKey, L"AutoReboot");
    state.nmi_crash_dump =
        platform::registry::read_dword(Hive::LocalMachine, kCrashControlKey, L"NMICrashDump");
    state.crash_on_ctrl_scroll = platform::registry::read_dword(
        Hive::LocalMachine, kCrashControlKey, L"CrashOnCtrlScroll");
    if (const auto file = platform::registry::read_string(Hive::LocalMachine, kCrashControlKey,
                                                          L"DumpFile")) {
        state.dump_file = *file;
    }
    state.readable = state.crash_dump_enabled.has_value();
    return state;
}

std::string describe_crash_dump_setting(std::uint32_t value) {
    switch (value) {
        case 0: return "none - a bugcheck would leave no dump at all";
        case 1: return "complete memory dump";
        case 2: return "kernel memory dump";
        case 3: return "small memory dump (minidump)";
        case 7: return "automatic memory dump";
        default: return "unrecognised value";
    }
}

// Whether a mitigation is currently in effect. `partial` means some schemes
// have it and others do not.
struct AppliedState {
    bool known = false;
    bool applied = false;
    bool partial = false;
    std::string detail;
};

AppliedState current_state(const Mitigation& mitigation,
                           const std::vector<platform::PowerScheme>& schemes) {
    AppliedState state;

    if (mitigation.kind == Kind::CrashControl) {
        const CrashControlState crash = read_crash_control();
        if (!crash.readable) {
            state.detail = "CrashControl is not readable";
            return state;
        }
        state.known = true;

        if (std::string_view(mitigation.name) == "dumps-on") {
            const std::uint32_t enabled = crash.crash_dump_enabled.value_or(0);
            const std::uint32_t reboot = crash.auto_reboot.value_or(1);
            state.applied = enabled != 0 && reboot == 0;
            state.detail = describe_crash_dump_setting(enabled) +
                           (reboot == 0 ? ", auto-reboot off" : ", auto-reboot on");
        } else {
            const bool nmi = crash.nmi_crash_dump.value_or(0) != 0;
            const bool scroll = crash.crash_on_ctrl_scroll.value_or(0) != 0;
            state.applied = nmi && scroll;
            state.detail = std::string(nmi ? "NMI dump on" : "NMI dump off") +
                           (scroll ? ", Ctrl+Scroll on" : ", Ctrl+Scroll off");
        }
        return state;
    }

    std::size_t matching = 0;
    std::size_t readable = 0;
    for (const platform::PowerScheme& scheme : schemes) {
        const platform::PowerSettingValue value =
            platform::read_processor_setting(scheme.guid, mitigation.setting_guid);
        if (!value.ok) continue;
        ++readable;
        if (value.ac == mitigation.target_ac && value.dc == mitigation.target_dc) ++matching;
        if (scheme.active) {
            state.detail = "active scheme: AC " + std::to_string(value.ac) + ", DC " +
                           std::to_string(value.dc);
        }
    }

    if (readable == 0) {
        state.detail = "not exposed on this machine";
        return state;
    }
    state.known = true;
    state.applied = matching == readable;
    state.partial = matching > 0 && matching < readable;
    return state;
}

// --- Confirmation ----------------------------------------------------------

bool confirm(const cli::CommandLine& cmdline, const std::string& question) {
    // Spec §2: "Every mutation is explicit, logged, reversible, and requires
    // either an interactive confirmation or --yes."
    if (cmdline.global.yes) return true;

    write_out(question + " [y/N] ");
    std::fflush(stdout);

    char answer = 0;
    if (std::fread(&answer, 1, 1, stdin) != 1) {
        write_out("\n");
        return false;
    }
    // Drain the rest of the line so a stray "yes" does not leak into a later
    // prompt.
    int c = answer;
    while (c != '\n' && c != EOF) c = std::fgetc(stdin);

    return answer == 'y' || answer == 'Y';
}

}  // namespace

int run_mitigate(const cli::CommandLine& cmdline, const text::Style& style) {
    if (cmdline.operands.empty()) {
        write_error("'mitigate' needs an action: list, apply or revert");
        write_out("  pm mitigate list\n"
                  "  pm mitigate apply <name> [--scheme all|<guid>] [--yes]\n"
                  "  pm mitigate revert <name> [--yes]\n");
        return exit_code::kUsage;
    }

    const std::string& action = cmdline.operands.front();
    const std::vector<platform::PowerScheme> schemes = platform::list_power_schemes();

    // ---- list ------------------------------------------------------------
    if (action == "list") {
        if (cmdline.global.json) {
            json::Writer writer(true);
            writer.begin_object();
            writer.key("mitigations").begin_array();
            for (const Mitigation& mitigation : mitigations()) {
                const AppliedState state = current_state(mitigation, schemes);
                writer.begin_object();
                writer.member("name", mitigation.name);
                writer.member("description", mitigation.description);
                writer.member("cost", mitigation.cost);
                writer.member_bool("state_known", state.known);
                writer.member_bool("applied", state.applied);
                writer.member_bool("partial", state.partial);
                writer.member("detail", state.detail);
                writer.end_object();
            }
            writer.end_array();
            writer.end_object();
            write_out(writer.take() + "\n");
            return exit_code::kSuccess;
        }

        std::string out = text::heading("Mitigations", style) + "\n";
        text::Table table({"Name", "State", "Detail"});
        for (const Mitigation& mitigation : mitigations()) {
            const AppliedState state = current_state(mitigation, schemes);
            std::string label = "unknown";
            if (state.known) {
                label = state.applied ? "applied" : (state.partial ? "partial" : "not applied");
            }
            table.add_row({mitigation.name, label, state.detail});
        }
        out += table.render(style);

        out += "\n";
        for (const Mitigation& mitigation : mitigations()) {
            out += text::paragraph(std::string(mitigation.name) + " - " + mitigation.description);
            out += text::bullet(std::string("Cost: ") + mitigation.cost, 4);
        }

        // Spec §4.9: detect and advise on the BIOS-level settings that cannot
        // be changed from Windows.
        out += "\n";
        out += text::heading("Not changeable from Windows", style);
        out += text::paragraph(
            "If the evidence points at idle-state instability - uncorrectable errors while the "
            "machine sits idle, no thermal or load correlation - the fix is usually in the "
            "BIOS, not here:");
        out += text::bullet(
            "Power Supply Idle Control -> Typical Current Idle. On most AM4 boards this is "
            "under Advanced > AMD CBS > Zen Common Options. This is the single most common fix "
            "for a Ryzen that resets at idle.", 4);
        out += text::bullet(
            "Global C-State Control -> Disabled, in the same menu, if Typical Current Idle "
            "alone does not settle it.", 4);
        out += text::bullet(
            "Precision Boost Overdrive and Curve Optimizer -> back to Auto/default. A negative "
            "curve offset is stable under load and unstable at idle, which matches exactly the "
            "pattern this tool detects.", 4);
        out += text::bullet(
            "Any memory overclock, including EXPO/XMP -> off, as a test. A memory controller "
            "error reports through the CPU's MCA banks and looks like a CPU fault.", 4);

        write_out(out);
        return exit_code::kSuccess;
    }

    if (action != "apply" && action != "revert") {
        write_error("unknown action '" + action + "'; expected list, apply or revert");
        return exit_code::kUsage;
    }

    if (cmdline.operands.size() < 2) {
        write_error("'" + action + "' needs a mitigation name; run 'pm mitigate list'");
        return exit_code::kUsage;
    }

    const std::string& name = cmdline.operands[1];
    const Mitigation* mitigation = find_mitigation(name);
    if (mitigation == nullptr) {
        write_error("unknown mitigation '" + name + "'; run 'pm mitigate list' for the six");
        return exit_code::kUsage;
    }

    if (!platform::is_elevated()) {
        write_error("changing this needs an elevated process; re-run pm from an "
                    "administrator prompt");
        return exit_code::kNeedsElevation;
    }

    // Which schemes to touch. Spec §4.9: all by default.
    std::vector<platform::PowerScheme> targets = schemes;
    if (const std::string* scheme = cmdline.option("scheme"); scheme != nullptr && *scheme != "all") {
        targets.clear();
        for (const platform::PowerScheme& candidate : schemes) {
            if (candidate.guid == *scheme || candidate.name == *scheme) targets.push_back(candidate);
        }
        if (targets.empty()) {
            write_error("no power scheme matches '" + *scheme + "'");
            return exit_code::kUsage;
        }
    }

    platform::StateStore store;
    const platform::StateLoad loaded = store.load();
    if (!loaded.ok && !loaded.missing) {
        write_error("cannot read the state file: " + loaded.error);
        return exit_code::kFailure;
    }

    // ---- revert ----------------------------------------------------------
    if (action == "revert") {
        const std::vector<platform::StateEntry> saved = store.entries_for(name);
        if (saved.empty()) {
            write_error("no snapshot for '" + name +
                        "' - it was never applied by this tool, and reverting from a guessed "
                        "default would be a second unannounced change rather than an undo");
            return exit_code::kFailure;
        }

        std::string question = "Restore " + std::to_string(saved.size()) +
                               " saved value(s) for '" + name + "'?";
        if (!confirm(cmdline, question)) {
            write_out("Nothing was changed.\n");
            return exit_code::kSuccess;
        }

        std::string out;
        bool all_ok = true;
        for (const platform::StateEntry& entry : saved) {
            if (entry.kind == "power") {
                const platform::PowerWriteResult result = platform::write_processor_setting(
                    entry.scope, entry.key, entry.previous_ac, entry.previous_dc);
                if (!result.ok) {
                    out += text::bullet("failed to restore scheme " + entry.scope + ": " +
                                        result.error);
                    all_ok = false;
                } else {
                    out += text::bullet("restored scheme " + entry.scope + " to AC " +
                                        std::to_string(entry.previous_ac) + ", DC " +
                                        std::to_string(entry.previous_dc));
                }
            } else if (entry.kind == "registry") {
                if (entry.previous_present) {
                    if (!platform::registry::write_dword(platform::registry::Hive::LocalMachine,
                                                         kCrashControlKey,
                                                         platform::to_utf16(entry.key).c_str(),
                                                         entry.previous_ac)) {
                        out += text::bullet("failed to restore " + entry.key);
                        all_ok = false;
                    } else {
                        out += text::bullet("restored " + entry.key + " to " +
                                            std::to_string(entry.previous_ac));
                    }
                } else {
                    out += text::bullet(entry.key +
                                        " did not exist before and was left as it is; deleting "
                                        "it would be a change the snapshot cannot justify");
                }
            }
        }

        // Re-applying the active scheme is what makes a written value take
        // effect now rather than at the next reboot; if it fails the restore
        // has happened on paper only, so say so.
        if (const platform::PowerWriteResult applied = platform::reapply_active_scheme();
            !applied.ok) {
            out += text::bullet(
                "the values were restored but the active power scheme could not be "
                "re-applied (" + applied.error + "), so they take effect at the next reboot");
        }
        store.remove(name);
        const platform::StateSave save = store.save();
        if (!save.ok) {
            out += text::bullet("warning: the state file could not be updated: " + save.error);
        }

        write_out(text::heading("Reverted " + name, style) + "\n" + out);
        return all_ok ? exit_code::kSuccess : exit_code::kFailure;
    }

    // ---- apply -----------------------------------------------------------
    std::string out;
    std::vector<platform::StateEntry> snapshot;

    if (mitigation->kind == Kind::PowerSetting) {
        std::string question = "Apply '" + name + "' to " + std::to_string(targets.size()) +
                               " power scheme(s)?";
        if (!confirm(cmdline, question)) {
            write_out("Nothing was changed.\n");
            return exit_code::kSuccess;
        }

        platform::unhide_processor_setting(mitigation->setting_guid);

        for (const platform::PowerScheme& scheme : targets) {
            const platform::PowerSettingValue before =
                platform::read_processor_setting(scheme.guid, mitigation->setting_guid);
            if (!before.ok) {
                out += text::bullet("scheme " + scheme.name + ": " + before.error + ", skipped");
                continue;
            }

            platform::StateEntry entry;
            entry.mitigation = name;
            entry.kind = "power";
            entry.scope = scheme.guid;
            entry.scope_name = scheme.name;
            entry.key = mitigation->setting_guid;
            entry.previous_ac = before.ac;
            entry.previous_dc = before.dc;
            entry.previous_present = true;
            entry.applied_at = now_seconds();
            snapshot.push_back(entry);

            const platform::PowerWriteResult result = platform::write_processor_setting(
                scheme.guid, mitigation->setting_guid, mitigation->target_ac,
                mitigation->target_dc);
            if (!result.ok) {
                out += text::bullet("scheme " + scheme.name + ": " + result.error);
            } else {
                out += text::bullet("scheme " + scheme.name + ": " + std::to_string(before.ac) +
                                    " -> " + std::to_string(mitigation->target_ac));
            }
        }
        if (const platform::PowerWriteResult applied = platform::reapply_active_scheme();
            !applied.ok) {
            out += text::bullet(
                "the values were written but the active power scheme could not be re-applied "
                "(" + applied.error + "), so they take effect at the next reboot");
        }
    } else {
        const CrashControlState before = read_crash_control();
        if (!before.readable) {
            write_error("cannot read CrashControl, so there is nothing to snapshot; refusing "
                        "to change a setting that could not then be undone");
            return exit_code::kFailure;
        }

        std::string question = "Apply '" + name + "' to the crash-dump configuration?";
        if (!confirm(cmdline, question)) {
            write_out("Nothing was changed.\n");
            return exit_code::kSuccess;
        }

        struct RegistryChange {
            const wchar_t* wide_name;
            const char* name;
            std::optional<std::uint32_t> previous;
            std::uint32_t target;
        };
        std::vector<RegistryChange> changes;

        if (name == "dumps-on") {
            changes.push_back({L"CrashDumpEnabled", "CrashDumpEnabled",
                               before.crash_dump_enabled, 2});   // kernel memory dump
            changes.push_back({L"AutoReboot", "AutoReboot", before.auto_reboot, 0});
        } else {
            changes.push_back({L"NMICrashDump", "NMICrashDump", before.nmi_crash_dump, 1});
            changes.push_back({L"CrashOnCtrlScroll", "CrashOnCtrlScroll",
                               before.crash_on_ctrl_scroll, 1});
        }

        for (const RegistryChange& change : changes) {
            platform::StateEntry entry;
            entry.mitigation = name;
            entry.kind = "registry";
            entry.scope = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl";
            entry.key = change.name;
            entry.previous_present = change.previous.has_value();
            entry.previous_ac = change.previous.value_or(0);
            entry.previous_dc = 0;
            entry.applied_at = now_seconds();
            snapshot.push_back(entry);

            if (!platform::registry::write_dword(platform::registry::Hive::LocalMachine,
                                                 kCrashControlKey, change.wide_name,
                                                 change.target)) {
                out += text::bullet(std::string("failed to write ") + change.name);
            } else {
                out += text::bullet(std::string(change.name) + ": " +
                                    (change.previous.has_value()
                                         ? std::to_string(*change.previous)
                                         : std::string("absent")) +
                                    " -> " + std::to_string(change.target));
            }
        }
    }

    for (const platform::StateEntry& entry : snapshot) store.add(entry);
    const platform::StateSave save = store.save();
    if (!save.ok) {
        out += text::bullet(
            "WARNING: the change was made but the snapshot could not be written (" +
            save.error + "), so 'pm mitigate revert " + name + "' will not be able to undo it");
    } else {
        out += text::bullet("snapshot written to " + save.path);
    }

    // Spec §4.9: verify a CPU-limit mitigation actually took effect.
    if (name == "max-cpu-99") {
        const platform::FrequencySample sample = platform::sample_frequencies();
        if (sample.ok && sample.nominal_mhz > 0) {
            if (sample.observed_percent > 100) {
                out += text::bullet(
                    "Verification: cores are still reaching " + std::to_string(sample.max_mhz) +
                    " MHz against a nominal " + std::to_string(sample.nominal_mhz) +
                    " MHz (" + std::to_string(sample.observed_percent) +
                    "%). On builds where CPPC drives the frequency, PROCTHROTTLEMAX is "
                    "silently ignored - this mitigation has not taken effect.");
            } else {
                out += text::bullet(
                    "Verification: no core exceeded " + std::to_string(sample.max_mhz) +
                    " MHz against a nominal " + std::to_string(sample.nominal_mhz) +
                    " MHz, consistent with the cap being honoured.");
            }
        } else {
            out += text::bullet(
                "Verification could not sample processor frequencies, so whether the cap took "
                "effect is unconfirmed.");
        }
    }

    write_out(text::heading("Applied " + name, style) + "\n" + out);
    return exit_code::kSuccess;
}

}  // namespace postmortem::commands
