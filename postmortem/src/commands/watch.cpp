// `pm watch` (spec §4.7, §8 milestone 9).

#include "commands/watch.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <mutex>

#include "commands/common.hpp"
#include "core/events/whea.hpp"
#include "core/json/writer.hpp"
#include "core/render/decode_view.hpp"
#include "core/text/format.hpp"
#include "platform/console.hpp"
#include "platform/cpu_info.hpp"
#include "platform/eventlog.hpp"
#include "platform/strings.hpp"

namespace postmortem::commands {
namespace {

// Set from the console control handler, which runs on its own thread, so the
// wait loop can notice Ctrl+C and tear the subscription down properly rather
// than letting the process be killed with the subscription still open.
std::atomic<bool> g_stop{false};

BOOL WINAPI console_handler(DWORD signal) {
    switch (signal) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            g_stop.store(true);
            return TRUE;   // handled; do not let the default handler kill us
        default:
            return FALSE;
    }
}

// One NDJSON line per event, appended and flushed immediately: the point of
// --log is to survive the crash that is about to happen.
class NdjsonLog {
public:
    bool open(const std::string& path, std::string& error) {
        const std::wstring wide = platform::to_utf16(path);
        if (_wfopen_s(&file_, wide.c_str(), L"ab") != 0 || file_ == nullptr) {
            error = "cannot open '" + path + "' for appending";
            return false;
        }
        path_ = path;
        return true;
    }

    void write(const std::string& line) {
        if (file_ == nullptr) return;
        std::fwrite(line.data(), 1, line.size(), file_);
        std::fputc('\n', file_);
        std::fflush(file_);
    }

    ~NdjsonLog() {
        if (file_ != nullptr) std::fclose(file_);
    }

    [[nodiscard]] bool is_open() const { return file_ != nullptr; }

private:
    std::FILE* file_ = nullptr;
    std::string path_;
};

}  // namespace

int run_watch(const cli::CommandLine& cmdline, const text::Style& style) {
    if (!cmdline.operands.empty()) {
        write_error("'watch' takes no positional arguments; got '" + cmdline.operands.front() +
                    "'");
        return exit_code::kUsage;
    }
    if (cmdline.global.evtx.has_value()) {
        write_error("--evtx reads a saved file; 'watch' subscribes to the live log, so the two "
                    "cannot be combined");
        return exit_code::kUsage;
    }

    NdjsonLog log;
    if (const std::string* path = cmdline.option("log")) {
        std::string error;
        if (!log.open(*path, error)) {
            write_error(error);
            return exit_code::kFailure;
        }
    }
    const std::string* exec_command = cmdline.option("exec");

    const cpu::Vendor vendor = platform::query_cpu_info().vendor;
    const text::TimeFormatter when = local_time_formatter();

    g_stop.store(false);
    ::SetConsoleCtrlHandler(console_handler, TRUE);

    std::string header = text::heading("Watching the System log for WHEA records", style);
    header += text::paragraph("Press Ctrl+C to stop.");
    if (log.is_open()) header += text::bullet("Appending NDJSON to the log file.");
    if (exec_command != nullptr) {
        header += text::bullet("Running the --exec command on each record.");
    }
    header += "\n";
    write_out(header);

    // The callback runs on the subscription's thread; serialise output so two
    // records arriving together do not interleave mid-line.
    std::mutex mutex;
    std::size_t seen = 0;

    const auto on_event = [&](const events::Event& event) {
        if (!events::is_whea_event(event)) return;

        events::WheaRecord record = events::from_event(event);
        events::decode(record, vendor);

        std::lock_guard<std::mutex> guard(mutex);
        ++seen;

        std::string out = "\n";
        out += text::heading(when(event.time) + "  WHEA event " +
                                 std::to_string(event.event_id),
                             style);
        if (record.status.has_value()) {
            const auto& verdict = record.status->verdict;
            std::string_view colour = style.value;
            switch (verdict.severity) {
                case mca::Severity::UncorrectedContextCorrupt: colour = style.bad; break;
                case mca::Severity::UncorrectedRecoverable:    colour = style.warn; break;
                case mca::Severity::Corrected:                 colour = style.good; break;
            }
            out.append(colour);
            out += text::paragraph(verdict.headline);
            out.append(style.reset);
        }

        text::KeyValueTable table;
        if (record.apic_id.has_value()) table.add("APIC", std::to_string(*record.apic_id));
        if (record.mca_bank.has_value()) table.add("Bank", std::to_string(*record.mca_bank));
        if (record.mci_stat.has_value()) {
            table.add("MCA_STATUS", text::to_hex(*record.mci_stat, 16));
        }
        if (record.mci_addr.has_value()) {
            std::string note;
            if (record.address.has_value()) note = record.address->classification_text;
            table.add("MCA_ADDR", text::to_hex(*record.mci_addr, 16), note);
        }
        if (!table.empty()) out += table.render(style);

        if (cmdline.global.verbose && record.status.has_value()) {
            out += "\n";
            out += render::status_text(*record.status, style);
        }
        write_out(out);

        if (log.is_open()) {
            json::Writer writer(false);   // one line per record
            writer.begin_object();
            writer.member_int("time_unix", event.time);
            writer.member("time_utc", text::format_utc(event.time));
            writer.member_uint("event_id", event.event_id);
            writer.member_uint("record_id", event.record_id);
            if (record.apic_id.has_value()) {
                writer.member_uint("apic_id", *record.apic_id);
            } else {
                writer.member_null("apic_id");
            }
            if (record.mca_bank.has_value()) {
                writer.member_uint("mca_bank", *record.mca_bank);
            } else {
                writer.member_null("mca_bank");
            }
            if (record.mci_stat.has_value()) {
                writer.member_hex("mci_stat", *record.mci_stat, 16);
            } else {
                writer.member_null("mci_stat");
            }
            if (record.mci_addr.has_value()) {
                writer.member_hex("mci_addr", *record.mci_addr, 16);
            } else {
                writer.member_null("mci_addr");
            }
            writer.member_bool("uncorrected", record.is_uncorrected());
            writer.member_bool("context_corrupt", record.is_context_corrupt());
            if (record.status.has_value()) {
                writer.member("headline", record.status->verdict.headline);
            }
            writer.end_object();
            log.write(writer.str());
        }

        if (exec_command != nullptr) {
            // std::system is enough here: the hook is a user-supplied command
            // and the shell is what they will expect to interpret it.
            const int status = std::system(exec_command->c_str());
            if (status != 0) {
                write_out(text::bullet("--exec command exited with " + std::to_string(status)));
            }
        }
    };

    const platform::SubscriptionResult result = platform::subscribe_events(
        {std::string(events::kWheaProvider)}, on_event, [] { return !g_stop.load(); });

    ::SetConsoleCtrlHandler(console_handler, FALSE);

    if (!result.ok) {
        write_error(result.error);
        return exit_code::kFailure;
    }

    write_out("\n" + text::paragraph("Stopped after " + std::to_string(seen) +
                                     " matching record(s). The subscription was closed."));
    return exit_code::kSuccess;
}

}  // namespace postmortem::commands
