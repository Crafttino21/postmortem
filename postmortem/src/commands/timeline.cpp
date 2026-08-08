// `pm timeline` and `pm analyze` (spec §4.5, §4.6; §8 milestones 6 and 7).

#include "commands/timeline.hpp"

#include <ctime>

#include "commands/common.hpp"
#include "core/events/analysis.hpp"
#include "core/events/crash_timeline.hpp"
#include "core/json/writer.hpp"
#include "core/text/format.hpp"
#include "platform/os_info.hpp"

namespace postmortem::commands {
namespace {

// Local hour of day for the time-of-day histogram. Kept here rather than in
// core so the analysis stays free of the C library's timezone handling.
unsigned local_hour_of(std::int64_t unix_seconds) {
    const std::string text = platform::format_local_time(unix_seconds);
    if (text.size() < 13) return 24;   // out of range, ignored by the caller
    const int tens = text[11] - '0';
    const int ones = text[12] - '0';
    if (tens < 0 || tens > 9 || ones < 0 || ones > 9) return 24;
    return static_cast<unsigned>(tens * 10 + ones);
}

std::string percentage(std::size_t part, std::size_t whole) {
    if (whole == 0) return "0%";
    return std::to_string(part * 100 / whole) + "%";
}

}  // namespace

int run_timeline(const cli::CommandLine& cmdline, const text::Style& style) {
    if (!cmdline.operands.empty()) {
        write_error("'timeline' takes no positional arguments; got '" +
                    cmdline.operands.front() + "'");
        return exit_code::kUsage;
    }

    LoadOptions options;
    options.all_providers = true;   // §4.5 correlates across providers
    const EventLoad load = load_events(cmdline, options);
    if (!load.ok) {
        write_error(load.error);
        return exit_code::kFailure;
    }

    const events::Timeline timeline =
        events::build_timeline(load.raw_events, load.incidents);
    const text::TimeFormatter when = local_time_formatter();

    if (cmdline.global.json) {
        json::Writer writer(true);
        writer.begin_object();
        writer.key("tool").begin_object();
        writer.member("name", "postmortem");
        writer.member("command", "timeline");
        writer.member("source", load.source);
        writer.end_object();
        writer.member("headline", timeline.headline);

        writer.key("sessions").begin_array();
        for (const events::Session& session : timeline.sessions) {
            writer.begin_object();
            writer.member_int("start_unix", session.start);
            writer.member("start_utc", text::format_utc(session.start));
            if (session.end.has_value()) {
                writer.member_int("end_unix", *session.end);
            } else {
                writer.member_null("end_unix");
            }
            writer.member_bool("ended_unexpectedly", session.ended_unexpectedly);
            writer.member_bool("had_bugcheck", session.had_bugcheck);
            writer.member_uint("whea_incidents", session.whea_incidents);
            writer.end_object();
        }
        writer.end_array();

        writer.key("entries").begin_array();
        for (const events::TimelineEntry& entry : timeline.entries) {
            writer.begin_object();
            writer.member_int("time_unix", entry.time);
            writer.member("time_utc", text::format_utc(entry.time));
            writer.member("kind", events::kind_text(entry.kind));
            writer.member("provider", entry.provider);
            writer.member_uint("event_id", entry.event_id);
            writer.member("summary", entry.summary);
            writer.member_uint("repeats", entry.repeats);
            if (entry.session.has_value()) {
                writer.member_uint("session", *entry.session);
            } else {
                writer.member_null("session");
            }
            if (entry.kernel_power.has_value()) {
                writer.key("kernel_power_41").begin_object();
                const auto& detail = *entry.kernel_power;
                if (detail.bugcheck_code.has_value()) {
                    writer.member_hex("bugcheck_code", *detail.bugcheck_code, 0);
                } else {
                    writer.member_null("bugcheck_code");
                }
                if (detail.whea_boot_error_count.has_value()) {
                    writer.member_uint("whea_boot_error_count", *detail.whea_boot_error_count);
                } else {
                    writer.member_null("whea_boot_error_count");
                }
                writer.end_object();
            }
            writer.key("notes").begin_array();
            for (const std::string& note : entry.notes) writer.value(note);
            writer.end_array();
            writer.end_object();
        }
        writer.end_array();

        writer.key("notes").begin_array();
        for (const std::string& note : timeline.notes) writer.value(note);
        writer.end_array();
        writer.end_object();
        write_out(writer.take() + "\n");
        return exit_code::kSuccess;
    }

    std::string out = text::heading("Crash timeline from " + load.source, style) + "\n";
    out += text::paragraph(timeline.headline);
    for (const std::string& note : timeline.notes) out += text::bullet(note);

    if (timeline.entries.empty()) {
        out += "\n";
        out += text::paragraph("Nothing in the selected range.");
        write_out(out);
        report_warnings(load, style);
        return exit_code::kSuccess;
    }

    out += "\n";
    text::Table table({"When", "Kind", "What"});
    std::optional<std::size_t> current_session;
    for (const events::TimelineEntry& entry : timeline.entries) {
        // A blank marker row between sessions makes the power cycles obvious.
        if (entry.session != current_session) {
            current_session = entry.session;
            if (entry.session.has_value()) {
                table.add_row({"", "", "--- boot session " +
                                           std::to_string(*entry.session + 1) + " ---"});
            }
        }
        std::string what = entry.summary;
        if (entry.repeats > 1) what += "  (x" + std::to_string(entry.repeats) + ")";
        table.add_row({when(entry.time), std::string(events::kind_text(entry.kind)), what});
    }
    out += table.render(style);

    // The reasoning belongs under the table, not inline, or the table stops
    // being scannable.
    bool any_notes = false;
    for (const events::TimelineEntry& entry : timeline.entries) {
        if (entry.notes.empty()) continue;
        if (!any_notes) {
            out += "\n";
            out += text::heading("What these mean", style);
            any_notes = true;
        }
        out += text::paragraph(when(entry.time) + "  " + entry.summary, 2);
        for (const std::string& note : entry.notes) out += text::bullet(note, 4);
    }

    write_out(out);
    report_warnings(load, style);
    return exit_code::kSuccess;
}

int run_analyze(const cli::CommandLine& cmdline, const text::Style& style) {
    if (!cmdline.operands.empty()) {
        write_error("'analyze' takes no positional arguments; got '" +
                    cmdline.operands.front() + "'");
        return exit_code::kUsage;
    }

    LoadOptions options;
    const EventLoad load = load_events(cmdline, options);
    if (!load.ok) {
        write_error(load.error);
        return exit_code::kFailure;
    }

    events::AnalysisInput input;
    input.incidents = load.incidents;
    input.local_hour = local_hour_of;
    if (!cmdline.global.evtx.has_value()) {
        input.install_date = platform::query_os_info().install_date;
    }

    const events::Analysis analysis = events::analyse(input);
    const text::TimeFormatter when = local_time_formatter();

    if (cmdline.global.json) {
        json::Writer writer(true);
        writer.begin_object();
        writer.key("tool").begin_object();
        writer.member("name", "postmortem");
        writer.member("command", "analyze");
        writer.member("source", load.source);
        writer.end_object();
        writer.member("verdict", analysis.verdict);
        writer.member_uint("incident_count", analysis.incident_count);
        writer.member_uint("record_count", analysis.record_count);
        writer.member("rate_trend", events::rate_trend_text(analysis.trend));
        if (analysis.median_interval.has_value()) {
            writer.member_int("median_interval_seconds", *analysis.median_interval);
        } else {
            writer.member_null("median_interval_seconds");
        }

        writer.key("per_apic").begin_array();
        for (const events::CountedValue& entry : analysis.per_apic) {
            writer.begin_object();
            writer.member_uint("apic_id", entry.value);
            writer.member_uint("incidents", entry.count);
            writer.end_object();
        }
        writer.end_array();

        writer.key("per_bank").begin_array();
        for (const events::CountedValue& entry : analysis.per_bank) {
            writer.begin_object();
            writer.member_uint("bank", entry.value);
            writer.member_uint("incidents", entry.count);
            writer.end_object();
        }
        writer.end_array();

        writer.key("addresses").begin_object();
        writer.member_bool("measurable", analysis.addresses.measurable);
        writer.member_bool("clustered", analysis.addresses.clustered);
        writer.member_uint("samples", analysis.addresses.sample_count);
        writer.member_uint("distinct_pages", analysis.addresses.distinct_pages);
        writer.end_object();

        writer.key("findings").begin_array();
        for (const events::Finding& finding : analysis.findings) {
            writer.begin_object();
            writer.member("claim", finding.claim);
            writer.member("reasoning", finding.reasoning);
            writer.member("confidence", events::confidence_text(finding.confidence));
            writer.end_object();
        }
        writer.end_array();
        writer.end_object();
        write_out(writer.take() + "\n");
        return exit_code::kSuccess;
    }

    // Spec §6: "Someone running pm analyze should see the conclusion in the
    // first three lines."
    std::string out = text::heading("Verdict", style) + "\n";
    out.append(style.value);
    out += text::paragraph(analysis.verdict);
    out.append(style.reset);

    if (analysis.incident_count == 0) {
        write_out(out);
        report_warnings(load, style);
        return exit_code::kSuccess;
    }

    out += "\n";
    out += text::heading("Evidence", style);
    for (const events::Finding& finding : analysis.findings) {
        std::string_view colour = style.dim;
        switch (finding.confidence) {
            case events::Confidence::Strong:   colour = style.bad; break;
            case events::Confidence::Moderate: colour = style.warn; break;
            case events::Confidence::Weak:     colour = style.dim; break;
        }
        out.append(colour);
        out += text::paragraph("[" + std::string(events::confidence_text(finding.confidence)) +
                                   "] " + finding.claim,
                               2);
        out.append(style.reset);
        out += text::paragraph(finding.reasoning, 6);
        out += "\n";
    }

    out += text::heading("Numbers", style);
    text::KeyValueTable numbers;
    numbers.add("Incidents", std::to_string(analysis.incident_count),
                std::to_string(analysis.record_count) + " raw records");
    if (analysis.first_seen.has_value()) numbers.add("First seen", when(*analysis.first_seen));
    if (analysis.last_seen.has_value()) numbers.add("Last seen", when(*analysis.last_seen));
    if (analysis.median_interval.has_value()) {
        numbers.add("Median interval", text::format_span(*analysis.median_interval));
    }
    if (analysis.mean_interval.has_value()) {
        numbers.add("Mean interval", text::format_span(*analysis.mean_interval));
    }
    numbers.add("Rate trend", std::string(events::rate_trend_text(analysis.trend)));
    if (analysis.install_date.has_value()) {
        numbers.add("OS installed", when(*analysis.install_date));
    }
    out += numbers.render(style);

    out += "\n";
    out += text::heading("Per core and per bank", style);
    text::Table distribution({"APIC", "Incidents", "Share"});
    for (const events::CountedValue& entry : analysis.per_apic) {
        distribution.add_row({std::to_string(entry.value), std::to_string(entry.count),
                              percentage(entry.count, analysis.incident_count)});
    }
    out += distribution.render(style);

    out += "\n";
    text::Table banks({"Bank", "Incidents", "Share"});
    for (const events::CountedValue& entry : analysis.per_bank) {
        banks.add_row({std::to_string(entry.value), std::to_string(entry.count),
                       percentage(entry.count, analysis.incident_count)});
    }
    out += banks.render(style);

    // Time of day, only when there is enough to be worth showing.
    if (analysis.incident_count >= 4) {
        out += "\n";
        out += text::heading("Time of day (local)", style);
        text::Table hours({"Hour", "Incidents"});
        for (unsigned hour = 0; hour < 24; ++hour) {
            if (analysis.by_hour[hour] == 0) continue;
            hours.add_row({std::to_string(hour) + ":00",
                           std::string(analysis.by_hour[hour], '#') + " " +
                               std::to_string(analysis.by_hour[hour])});
        }
        out += hours.render(style);
        out += text::bullet(
            "A concentration in idle hours points at deep C-states or low-load voltage; a "
            "concentration under load points at thermals or current delivery.");
    }

    write_out(out);
    report_warnings(load, style);
    return exit_code::kSuccess;
}

}  // namespace postmortem::commands
