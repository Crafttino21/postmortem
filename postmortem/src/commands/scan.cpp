// `pm scan` and `pm show` (spec §5, §8 milestone 4).

#include "commands/scan.hpp"

#include <string>

#include "commands/common.hpp"
#include "core/events/grouping.hpp"
#include "core/input/values.hpp"
#include "core/json/writer.hpp"
#include "core/render/event_view.hpp"
#include "core/text/format.hpp"
#include "platform/cpu_topology.hpp"

namespace postmortem::commands {
namespace {

// Spec §4.4: an APIC ID means nothing to a user. When the scan runs on the
// affected machine the physical location can be resolved; from a .evtx it
// cannot, and saying so is better than printing a guess.
std::string describe_cores(const std::vector<unsigned>& apic_ids,
                           const platform::TopologyMap& topology) {
    if (!topology.available) return {};

    std::string out;
    for (const unsigned apic : apic_ids) {
        const platform::LogicalProcessor* processor = topology.find_by_apic_id(apic);
        if (processor == nullptr) continue;
        if (!out.empty()) out += ", ";
        out += processor->describe();
    }
    return out;
}

}  // namespace

int run_scan(const cli::CommandLine& cmdline, const text::Style& style) {
    if (!cmdline.operands.empty()) {
        write_error("'scan' takes no positional arguments; got '" + cmdline.operands.front() +
                    "'");
        return exit_code::kUsage;
    }

    LoadOptions options;
    options.decode_records = false;   // the summary needs only the status bits
    const EventLoad load = load_events(cmdline, options);
    if (!load.ok) {
        write_error(load.error);
        return exit_code::kFailure;
    }

    render::IncidentOptions view;
    view.verbose = cmdline.global.verbose;
    view.time = local_time_formatter();

    // --group-by: a frequency tally instead of a history.
    if (const std::string* fields_text = cmdline.option("group-by")) {
        const events::GroupFieldList fields = events::parse_group_fields(*fields_text);
        if (!fields.ok) {
            write_error("--group-by: " + fields.error);
            std::string help = "Available fields:\n";
            for (const events::GroupFieldSpec& spec : events::group_field_specs()) {
                std::string name(spec.name);
                while (name.size() < 12) name += ' ';
                help += "  " + name + std::string(spec.description) + "\n";
            }
            write_out(help);
            return exit_code::kUsage;
        }

        const std::vector<const events::WheaRecord*> records = flatten_records(load);
        const events::Grouping grouping =
            events::group_records(records, fields.fields, load.vendor, view.time);

        if (cmdline.global.json) {
            json::Writer writer(true);
            writer.begin_object();
            writer.key("tool").begin_object();
            writer.member("name", "postmortem");
            writer.member("command", "scan");
            writer.member("view", "group-by");
            writer.member("source", load.source);
            writer.end_object();
            writer.key("grouping");
            render::grouping_json(grouping, writer);
            writer.end_object();
            write_out(writer.take() + "\n");
            return exit_code::kSuccess;
        }

        write_out(text::heading("WHEA records from " + load.source + ", grouped", style) + "\n" +
                  render::grouping_table(grouping, style, view));
        report_warnings(load, style);
        return exit_code::kSuccess;
    }

    // --records: every raw record, uncollapsed.
    if (cmdline.has_option("records")) {
        const std::vector<const events::WheaRecord*> records = flatten_records(load);

        if (cmdline.global.json) {
            json::Writer writer(true);
            writer.begin_object();
            writer.key("tool").begin_object();
            writer.member("name", "postmortem");
            writer.member("command", "scan");
            writer.member("view", "records");
            writer.member("source", load.source);
            writer.end_object();
            writer.member_uint("record_count", records.size());
            writer.key("records");
            render::record_json(records, load.vendor, writer);
            writer.end_object();
            write_out(writer.take() + "\n");
            return exit_code::kSuccess;
        }

        write_out(text::heading("WHEA records from " + load.source, style) + "\n" +
                  render::record_table(records, load.vendor, style, view));
        report_warnings(load, style);
        return exit_code::kSuccess;
    }

    // Topology is only meaningful for the live log.
    platform::TopologyMap topology;
    if (!cmdline.global.evtx.has_value()) topology = platform::query_topology();

    if (cmdline.global.json) {
        json::Writer writer(true);
        writer.begin_object();
        writer.key("tool").begin_object();
        writer.member("name", "postmortem");
        writer.member("command", "scan");
        writer.member("source", load.source);
        writer.end_object();
        writer.member_uint("incident_count", load.incidents.size());
        writer.key("incidents").begin_array();
        for (const events::Incident& incident : load.incidents) {
            render::incident_json(incident, writer, false);
        }
        writer.end_array();
        writer.key("warnings").begin_array();
        for (const std::string& warning : load.warnings) writer.value(warning);
        writer.end_array();
        writer.end_object();
        write_out(writer.take() + "\n");
        return exit_code::kSuccess;
    }

    std::string out = text::heading("WHEA records from " + load.source, style) + "\n";
    out += render::incident_table(load.incidents, style, view);

    // Per-incident core mapping, when we can do it honestly.
    if (topology.available && !load.incidents.empty()) {
        out += "\n";
        out += text::heading("Reporting cores", style);
        text::KeyValueTable table;
        for (std::size_t i = 0; i < load.incidents.size(); ++i) {
            const std::string cores = describe_cores(load.incidents[i].apic_ids, topology);
            if (cores.empty()) continue;
            table.add("Incident " + std::to_string(i + 1), cores);
        }
        if (table.empty()) {
            out += text::bullet(
                "none of the reported APIC IDs matched a processor on this machine; the "
                "records may come from a different CPU");
        } else {
            out += table.render(style);
        }
    } else if (!load.incidents.empty()) {
        out += "\n";
        out += text::bullet(
            "APIC IDs are not mapped to physical cores here because the records did not come "
            "from this machine; run 'pm topology' on the affected machine to resolve them");
    }

    if (!load.incidents.empty()) {
        out += "\n";
        out += text::paragraph("Run 'pm show <n>' for the full decode of one incident.");
    }

    write_out(out);
    report_warnings(load, style);
    return exit_code::kSuccess;
}

int run_show(const cli::CommandLine& cmdline, const text::Style& style) {
    if (cmdline.operands.size() != 1) {
        write_error("'show' needs exactly one incident number, e.g. 'pm show 1'");
        return exit_code::kUsage;
    }

    const input::IntegerResult index = input::parse_u64(cmdline.operands.front());
    if (!index.ok || index.value == 0) {
        write_error("'" + cmdline.operands.front() +
                    "' is not an incident number; they start at 1, as listed by 'pm scan'");
        return exit_code::kUsage;
    }

    LoadOptions options;
    options.decode_records = true;   // show is the full decode
    const EventLoad load = load_events(cmdline, options);
    if (!load.ok) {
        write_error(load.error);
        return exit_code::kFailure;
    }

    if (index.value > load.incidents.size()) {
        write_error("there is no incident " + std::to_string(index.value) + "; " +
                    (load.incidents.empty()
                         ? std::string("the selected range holds no WHEA records at all")
                         : "the range holds " + std::to_string(load.incidents.size())));
        return exit_code::kFailure;
    }

    const std::size_t position = static_cast<std::size_t>(index.value) - 1;
    const events::Incident& incident = load.incidents[position];

    if (cmdline.global.json) {
        json::Writer writer(true);
        writer.begin_object();
        writer.key("tool").begin_object();
        writer.member("name", "postmortem");
        writer.member("command", "show");
        writer.member("source", load.source);
        writer.end_object();
        writer.member_uint("incident_index", index.value);
        writer.key("incident");
        render::incident_json(incident, writer, true);
        writer.end_object();
        write_out(writer.take() + "\n");
        return exit_code::kSuccess;
    }

    render::IncidentOptions render_options;
    render_options.verbose = cmdline.global.verbose;
    render_options.time = local_time_formatter();

    write_out(render::incident_detail(incident, position, style, render_options));
    report_warnings(load, style);
    return exit_code::kSuccess;
}

}  // namespace postmortem::commands
