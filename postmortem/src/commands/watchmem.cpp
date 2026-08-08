// `pm watch-mem` - live byte-level view of another process's memory.

#include "commands/watchmem.hpp"

#include <windows.h>

#include <atomic>
#include <chrono>

#include "commands/common.hpp"
#include "core/input/values.hpp"
#include "core/json/writer.hpp"
#include "core/render/watch_view.hpp"
#include "core/text/format.hpp"
#include "platform/memory.hpp"
#include "platform/screen.hpp"

namespace postmortem::commands {
namespace {

std::atomic<bool> g_stop{false};

BOOL WINAPI console_handler(DWORD signal) {
    switch (signal) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            g_stop.store(true);
            return TRUE;
        default:
            return FALSE;
    }
}

std::int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string protection(const platform::MemoryRegion& region) {
    std::string text;
    text += region.readable ? 'r' : '-';
    text += region.writable ? 'w' : '-';
    text += region.executable ? 'x' : '-';
    return text;
}

int list_regions(const platform::ProcessMemory& memory, const platform::ProcessTarget& target,
                 const cli::CommandLine& cmdline, const text::Style& style) {
    const std::vector<platform::MemoryRegion> regions = memory.regions();

    if (cmdline.global.json) {
        json::Writer writer(true);
        writer.begin_object();
        writer.member_uint("process_id", target.process_id);
        writer.member("process_name", target.name);
        writer.key("regions").begin_array();
        for (const platform::MemoryRegion& region : regions) {
            writer.begin_object();
            writer.member_hex("base", region.base, 16);
            writer.member_uint("size", region.size);
            writer.member("protection", protection(region));
            writer.member_bool("image", region.image);
            writer.member("module", region.module);
            writer.end_object();
        }
        writer.end_array();
        writer.end_object();
        write_out(writer.take() + "\n");
        return exit_code::kSuccess;
    }

    std::string out = text::heading(
        "Committed regions in " + target.name + " (" + std::to_string(target.process_id) + ")",
        style);
    out += "\n";

    text::Table table({"Base", "Size", "Prot", "Type", "Module"});
    for (const platform::MemoryRegion& region : regions) {
        table.add_row({text::to_hex(region.base, 16),
                       std::to_string(region.size / 1024) + " KiB", protection(region),
                       region.image ? "image" : (region.is_private ? "private" : "mapped"),
                       region.module});
    }
    out += table.render(style);
    out += "\n";
    out += text::paragraph("Pick a readable base and pass it as --at, e.g. --at " +
                           (regions.empty() ? std::string("0x7FF6A2C10000")
                                            : text::to_hex(regions.front().base, 0)));
    write_out(out);
    return exit_code::kSuccess;
}

}  // namespace

int run_watch_mem(const cli::CommandLine& cmdline, const text::Style& style) {
    if (!cmdline.operands.empty()) {
        write_error("'watch-mem' takes options, not positional arguments; got '" +
                    cmdline.operands.front() + "'");
        return exit_code::kUsage;
    }

    const std::string* pid_text = cmdline.option("pid");
    if (pid_text == nullptr) {
        write_error("'watch-mem' needs --pid <id or name>");
        write_out("  pm watch-mem --pid notepad --regions\n"
                  "  pm watch-mem --pid 4812 --at 0x7FF6A2C10000 --len 256\n"
                  "  pm watch-mem --pid myapp --module myapp.exe --offset 0x1000\n");
        return exit_code::kUsage;
    }

    const platform::ProcessLookup lookup = platform::find_process(*pid_text);
    if (!lookup.ok) {
        write_error(lookup.error);
        for (const auto& [pid, name] : lookup.candidates) {
            write_out("  " + std::to_string(pid) + "  " + name + "\n");
        }
        return exit_code::kFailure;
    }

    platform::ProcessMemory memory;
    const platform::ProcessTarget target = memory.open(lookup.process_id);
    if (!target.ok) {
        write_error(target.error);
        return exit_code::kFailure;
    }

    if (cmdline.has_option("regions")) {
        return list_regions(memory, target, cmdline, style);
    }

    // Address: either --at directly, or --module plus an optional --offset.
    std::uint64_t address = 0;
    std::string address_label;
    if (const std::string* at = cmdline.option("at")) {
        const input::IntegerResult parsed = input::parse_u64(*at);
        if (!parsed.ok) {
            write_error("--at: " + parsed.error);
            return exit_code::kUsage;
        }
        address = parsed.value;
    } else if (const std::string* module = cmdline.option("module")) {
        const std::uint64_t base = memory.module_base(*module);
        if (base == 0) {
            write_error("'" + *module + "' is not loaded in that process; run with --regions "
                        "to see what is");
            return exit_code::kFailure;
        }
        std::uint64_t offset = 0;
        if (const std::string* offset_text = cmdline.option("offset")) {
            const input::IntegerResult parsed = input::parse_u64(*offset_text);
            if (!parsed.ok) {
                write_error("--offset: " + parsed.error);
                return exit_code::kUsage;
            }
            offset = parsed.value;
        }
        address = base + offset;
        address_label = *module + "+" + text::to_hex(offset, 0);
    } else {
        write_error("'watch-mem' needs --at <address>, or --module <name> [--offset <n>]; "
                    "run with --regions to see what is mapped");
        return exit_code::kUsage;
    }

    std::size_t length = 256;
    if (const std::string* len_text = cmdline.option("len")) {
        const input::IntegerResult parsed = input::parse_u64(*len_text);
        if (!parsed.ok || parsed.value == 0) {
            write_error("--len: " + (parsed.ok ? std::string("must be non-zero")
                                               : parsed.error));
            return exit_code::kUsage;
        }
        // A hex dump beyond this is unreadable anyway, and the per-tick diff
        // cost grows with it.
        length = static_cast<std::size_t>(std::min<std::uint64_t>(parsed.value, 4096));
    }

    double interval = 1.0;
    if (const std::string* text = cmdline.option("interval")) {
        const input::DurationResult parsed = input::parse_duration(*text);
        if (!parsed.ok || parsed.milliseconds <= 0) {
            write_error("--interval: " + (parsed.ok ? std::string("must be positive")
                                                    : parsed.error));
            return exit_code::kUsage;
        }
        interval = static_cast<double>(parsed.milliseconds) / 1000.0;
    }
    interval = std::max(0.05, interval);

    g_stop.store(false);
    ::SetConsoleCtrlHandler(console_handler, TRUE);

    platform::Screen screen;
    const bool full_screen = screen.enter();

    render::MemoryWatch watch;
    watch.process_id = target.process_id;
    watch.process_name = target.name;
    watch.address = address;
    watch.address_label = address_label;
    watch.interval_seconds = interval;
    watch.change_counts.assign(length, 0);

    std::vector<std::uint8_t> previous;
    bool have_previous = false;
    bool paused = false;
    const text::TimeFormatter when = local_time_formatter();

    while (!g_stop.load()) {
        if (!paused) {
            std::vector<std::uint8_t> current;
            std::size_t readable = 0;
            const bool ok = memory.read(address, length, current, readable);

            watch.error.clear();
            if (!ok && readable == 0) {
                watch.error = "the region is no longer readable - it may have been freed or "
                              "the protection changed";
            }

            watch.changed_now.assign(length, false);
            if (have_previous) {
                for (std::size_t i = 0; i < length && i < readable; ++i) {
                    if (current[i] != previous[i]) {
                        watch.changed_now[i] = true;
                        if (i < watch.change_counts.size()) ++watch.change_counts[i];
                    }
                }
            }

            watch.bytes = current;
            watch.readable = readable;
            previous = std::move(current);
            have_previous = true;
            ++watch.ticks;
        }

        watch.clock = when(now_seconds());
        watch.paused = paused;

        const platform::ScreenSize size =
            full_screen ? screen.size() : platform::ScreenSize{100, 40};
        const std::string frame = render::memory_frame(watch, style, size.columns, size.rows);
        if (full_screen) {
            screen.draw(frame);
        } else {
            write_out(frame + "\n");
        }

        // Sleep in slices so keys and Ctrl+C are noticed promptly.
        const auto slice = static_cast<DWORD>(std::max(10.0, interval * 1000.0 / 8.0));
        for (int i = 0; i < 8 && !g_stop.load(); ++i) {
            const int key = full_screen ? platform::poll_key() : 0;
            if (key == 'q' || key == 'Q' || key == 3) {
                g_stop.store(true);
                break;
            }
            if (key == ' ') paused = !paused;
            if (key == 'r' || key == 'R') {
                watch.change_counts.assign(length, 0);
                watch.ticks = 0;
            }
            ::Sleep(slice);
        }
    }

    screen.leave();
    ::SetConsoleCtrlHandler(console_handler, FALSE);
    write_out(text::paragraph("Stopped. The process was never suspended and nothing was "
                              "written to it."));
    return exit_code::kSuccess;
}

}  // namespace postmortem::commands
