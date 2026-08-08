// `pm live` - live view of CPU activity.

#include "commands/live.hpp"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <mutex>

#include "commands/common.hpp"
#include "core/events/whea.hpp"
#include "core/input/values.hpp"
#include "core/render/live_view.hpp"
#include "core/text/format.hpp"
#include "platform/cpu_info.hpp"
#include "platform/cpu_topology.hpp"
#include "platform/etw.hpp"
#include "platform/eventlog.hpp"
#include "platform/os_info.hpp"
#include "platform/perf.hpp"
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

}  // namespace

int run_live(const cli::CommandLine& cmdline, const text::Style& style) {
    if (!cmdline.operands.empty()) {
        write_error("'live' takes no positional arguments; got '" + cmdline.operands.front() +
                    "'");
        return exit_code::kUsage;
    }
    if (cmdline.global.evtx.has_value()) {
        write_error("--evtx reads a saved file; 'live' watches the running machine, so the two "
                    "cannot be combined");
        return exit_code::kUsage;
    }

    double interval = 1.0;
    if (const std::string* text = cmdline.option("interval")) {
        const input::DurationResult parsed = input::parse_duration(*text);
        if (!parsed.ok || parsed.seconds <= 0) {
            write_error("--interval: " + (parsed.ok ? std::string("must be positive")
                                                    : parsed.error));
            return exit_code::kUsage;
        }
        interval = static_cast<double>(parsed.seconds);
    }
    // PDH rate counters need a measurable window; below a quarter second the
    // numbers are noise rather than data.
    interval = std::max(0.25, interval);

    platform::PerfMonitor perf;
    std::string perf_error;
    if (!perf.open(perf_error)) {
        write_error(perf_error);
        return exit_code::kFailure;
    }

    const platform::CpuInfo cpu = platform::query_cpu_info();
    const platform::TopologyMap topology = platform::query_topology();

    // ETW is optional: it needs elevation, and the whole view still works
    // without it (spec §2's degrade-gracefully rule).
    platform::EtwSession etw;
    std::string etw_note;
    if (cmdline.has_option("no-etw")) {
        etw_note = "disabled with --no-etw";
    } else if (!platform::is_elevated()) {
        etw_note = "needs an elevated prompt";
    } else {
        std::string error;
        if (!etw.start(cpu.logical_processors, error)) etw_note = error;
    }

    // How many WHEA records the log already holds, so the feed can say
    // "nothing new" rather than looking empty.
    std::size_t known_incidents = 0;
    {
        LoadOptions options;
        const EventLoad load = load_events(cmdline, options);
        if (load.ok) known_incidents = load.incidents.size();
    }

    // The live feed is filled from the subscription thread.
    std::mutex feed_mutex;
    std::vector<render::LiveIncident> feed;
    const text::TimeFormatter when = local_time_formatter();

    std::atomic<bool> subscription_running{true};
    const auto on_event = [&](const events::Event& event) {
        if (!events::is_whea_event(event)) return;

        events::WheaRecord record = events::from_event(event);
        events::decode(record, cpu.vendor);

        render::LiveIncident incident;
        incident.when = when(event.time);
        incident.fatal = record.is_uncorrected() && record.is_context_corrupt();
        incident.text = record.status.has_value()
                            ? record.status->verdict.headline
                            : "WHEA event " + std::to_string(event.event_id);
        if (record.apic_id.has_value()) {
            incident.text += "  (APIC " + std::to_string(*record.apic_id) + ")";
        }

        std::lock_guard<std::mutex> guard(feed_mutex);
        feed.push_back(std::move(incident));
        if (feed.size() > 6) feed.erase(feed.begin());
    };

    std::thread subscriber([&]() {
        const platform::SubscriptionResult result = platform::subscribe_events(
            {std::string(events::kWheaProvider)}, on_event,
            [&] { return subscription_running.load() && !g_stop.load(); });
        (void)result;
    });

    g_stop.store(false);
    ::SetConsoleCtrlHandler(console_handler, TRUE);

    platform::Screen screen;
    const bool full_screen = screen.enter();
    if (!full_screen) {
        write_out(text::paragraph(
            "stdout is not a console, so 'live' cannot take over the screen; printing one "
            "snapshot per interval instead. Redirect to a file only if that is what you want."));
    }

    const platform::OsInfo os = platform::query_os_info();
    bool paused = false;
    unsigned sort_by_activity = 0;
    int exit_status = exit_code::kSuccess;

    const auto sleep_slice = static_cast<DWORD>(interval * 1000.0 / 8.0);

    while (!g_stop.load()) {
        const platform::PerfSnapshot sample = perf.sample();
        const platform::EtwCounts etw_counts = etw.running() ? etw.take() : platform::EtwCounts{};

        if (!sample.ok) {
            exit_status = exit_code::kFailure;
            if (full_screen) screen.leave();
            write_error(sample.error);
            break;
        }

        render::LiveSnapshot snapshot;
        snapshot.cpu_brand = cpu.brand.empty() ? "unknown CPU" : cpu.brand;
        snapshot.nominal_mhz = cpu.nominal_mhz.value_or(0);
        snapshot.uptime = platform::format_duration(::GetTickCount64());
        snapshot.clock = when(now_seconds());
        snapshot.interval_seconds = interval;
        snapshot.etw_active = etw.running();
        snapshot.etw_note = etw_note;
        snapshot.known_incidents = known_incidents;
        snapshot.paused = paused;
        snapshot.sort_by_activity = sort_by_activity;
        snapshot.total_busy_percent = sample.total.processor_time;
        snapshot.notes = sample.missing_counters.empty()
                             ? std::vector<std::string>{}
                             : std::vector<std::string>{
                                   "counters not published by this machine: " +
                                   [&] {
                                       std::string list;
                                       for (const std::string& name : sample.missing_counters) {
                                           if (!list.empty()) list += ", ";
                                           list += name;
                                       }
                                       return list;
                                   }()};

        for (const platform::CoreSample& core : sample.cores) {
            render::LiveCore row;
            row.os_index = core.os_index;
            // "% Processor Performance" is the actual clock as a percentage of
            // nominal, which is the number that moves. The "Processor
            // Frequency" counter is documented as the slowest processor's
            // frequency and in practice reports the static nominal value, so
            // it is only a fallback.
            const double nominal = static_cast<double>(cpu.nominal_mhz.value_or(0));
            row.frequency_mhz = (core.processor_performance > 0 && nominal > 0)
                                    ? nominal * core.processor_performance / 100.0
                                    : core.frequency_mhz;
            row.performance_percent = core.processor_performance;
            row.busy_percent = core.processor_time;
            row.c1_percent = core.c1_time;
            row.c2_percent = core.c2_time;
            row.c3_percent = core.c3_time;
            row.parked = core.parked;
            row.interrupts_per_sec = core.interrupts_per_sec;
            row.dpcs_per_sec = core.dpcs_per_sec;

            if (etw.running() && core.os_index < etw_counts.context_switches.size()) {
                row.context_switches_per_sec =
                    static_cast<double>(etw_counts.context_switches[core.os_index]) / interval;
                row.etw_dpcs_per_sec =
                    static_cast<double>(etw_counts.dpcs[core.os_index]) / interval;
                row.etw_interrupts_per_sec =
                    static_cast<double>(etw_counts.interrupts[core.os_index]) / interval;
            }

            if (topology.available && core.os_index < topology.processors.size()) {
                const platform::LogicalProcessor& processor = topology.processors[core.os_index];
                row.core_id = processor.core_id;
                row.thread_id = processor.thread_id;
                row.l3_complex = processor.l3_complex;
            }

            snapshot.cores.push_back(row);
        }

        {
            std::lock_guard<std::mutex> guard(feed_mutex);
            snapshot.live_incidents = feed;
        }

        const platform::ScreenSize size =
            full_screen ? screen.size() : platform::ScreenSize{100, 60};
        const std::string frame =
            render::live_frame(snapshot, style, size.columns, size.rows);

        if (full_screen) {
            screen.draw(frame);
        } else {
            write_out(frame + "\n");
        }

        // Sleep in slices so a keypress or Ctrl+C is noticed promptly rather
        // than after a whole interval.
        for (int slice = 0; slice < 8 && !g_stop.load(); ++slice) {
            const int key = full_screen ? platform::poll_key() : 0;
            if (key == 'q' || key == 'Q' || key == 3 /* Ctrl+C */) {
                g_stop.store(true);
                break;
            }
            if (key == ' ') paused = !paused;
            if (key == 's' || key == 'S') sort_by_activity = sort_by_activity == 0 ? 1u : 0u;
            if (key == 'r' || key == 'R') {
                std::lock_guard<std::mutex> guard(feed_mutex);
                feed.clear();
            }
            ::Sleep(sleep_slice);
        }

        // While paused, keep collecting so the rate counters stay honest but
        // leave the frame as it is.
        while (paused && !g_stop.load()) {
            const int key = full_screen ? platform::poll_key() : 0;
            if (key == 'q' || key == 'Q' || key == 3) {
                g_stop.store(true);
            } else if (key == ' ') {
                paused = false;
            }
            ::Sleep(50);
        }
    }

    subscription_running.store(false);
    g_stop.store(true);
    if (subscriber.joinable()) subscriber.join();

    etw.stop();
    perf.close();
    screen.leave();
    ::SetConsoleCtrlHandler(console_handler, FALSE);

    if (exit_status == exit_code::kSuccess) {
        write_out(text::paragraph("Stopped. The ETW session and event subscription were "
                                  "closed."));
    }
    return exit_status;
}

}  // namespace postmortem::commands
