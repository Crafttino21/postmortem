// `pm topology` (spec §4.4, §8 milestone 5).

#include "commands/topology.hpp"

#include "commands/common.hpp"
#include "core/json/writer.hpp"
#include "core/text/format.hpp"

namespace postmortem::commands {

int run_topology(const cli::CommandLine& cmdline, const text::Style& style) {
    if (!cmdline.operands.empty()) {
        write_error("'topology' takes no arguments; got '" + cmdline.operands.front() + "'");
        return exit_code::kUsage;
    }

    const platform::TopologyMap map = platform::query_topology();

    if (cmdline.global.json) {
        json::Writer writer(true);
        writer.begin_object();
        writer.key("tool").begin_object();
        writer.member("name", "postmortem");
        writer.member("command", "topology");
        writer.end_object();
        writer.member_bool("available", map.available);
        writer.member("error", map.error);
        writer.member("vendor", map.vendor);
        writer.member_bool("hybrid", map.hybrid);
        writer.member_uint("physical_cores", map.physical_cores);
        writer.member_uint("l3_complexes", map.l3_complexes);

        writer.key("processors").begin_array();
        for (const platform::LogicalProcessor& processor : map.processors) {
            writer.begin_object();
            writer.member_uint("os_index", processor.os_index);
            writer.member_uint("group", processor.group);
            writer.member_uint("index_in_group", processor.index_in_group);
            writer.member_uint("apic_id", processor.apic_id);
            writer.member_bool("apic_id_is_x2", processor.apic_id_is_x2);
            const auto optional_uint = [&](std::string_view name,
                                           const std::optional<unsigned>& value) {
                if (value.has_value()) {
                    writer.member_uint(name, *value);
                } else {
                    writer.member_null(name);
                }
            };
            optional_uint("core_id", processor.core_id);
            optional_uint("thread_id", processor.thread_id);
            optional_uint("package_id", processor.package_id);
            optional_uint("l3_complex", processor.l3_complex);
            if (processor.is_performance_core.has_value()) {
                writer.member_bool("performance_core", *processor.is_performance_core);
            } else {
                writer.member_null("performance_core");
            }
            writer.end_object();
        }
        writer.end_array();

        writer.key("caveats").begin_array();
        for (const std::string& caveat : map.caveats) writer.value(caveat);
        writer.end_array();
        writer.end_object();
        write_out(writer.take() + "\n");
        return map.available ? exit_code::kSuccess : exit_code::kFailure;
    }

    if (!map.available) {
        write_error("cannot enumerate the CPU topology: " + map.error);
        return exit_code::kFailure;
    }

    std::string out = text::heading("CPU topology", style) + "\n";

    text::KeyValueTable summary;
    summary.add("Vendor", map.vendor.empty() ? "unknown" : map.vendor);
    summary.add("Logical processors", std::to_string(map.processors.size()));
    summary.add("Physical cores", std::to_string(map.physical_cores));
    summary.add("L3 complexes", std::to_string(map.l3_complexes),
                map.l3_complexes > 1 ? "CCX/CCD on AMD, cluster on Intel" : "");
    if (map.hybrid) summary.add("Hybrid", "yes", "P-cores and E-cores are labelled below");
    out += summary.render(style);

    out += "\n";
    text::Table table({"CPU", "APIC", "Core", "Thread", "L3", "Type", "Group"});
    for (const platform::LogicalProcessor& processor : map.processors) {
        const auto text_or_dash = [](const std::optional<unsigned>& value) {
            return value.has_value() ? std::to_string(*value) : std::string("?");
        };
        std::string type = "-";
        if (processor.is_performance_core.has_value()) {
            type = *processor.is_performance_core ? "P" : "E";
        }
        table.add_row({std::to_string(processor.os_index),
                       processor.apic_id_is_x2 ? std::to_string(processor.apic_id)
                                               : std::to_string(processor.apic_id) + " (8-bit)",
                       text_or_dash(processor.core_id), text_or_dash(processor.thread_id),
                       text_or_dash(processor.l3_complex), type,
                       std::to_string(processor.group) + ":" +
                           std::to_string(processor.index_in_group)});
    }
    out += table.render(style);

    if (!map.caveats.empty()) {
        out += "\n";
        out += text::heading("Uncertain", style);
        for (const std::string& caveat : map.caveats) out += text::bullet(caveat);
    }

    write_out(out);
    return exit_code::kSuccess;
}

}  // namespace postmortem::commands
