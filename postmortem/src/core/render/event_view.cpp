#include "core/render/event_view.hpp"

#include "core/render/decode_view.hpp"

namespace postmortem::render {
namespace {

using text::to_hex;

std::string join_numbers(const std::vector<unsigned>& values) {
    std::string out;
    for (const unsigned value : values) {
        if (!out.empty()) out += ",";
        out += std::to_string(value);
    }
    return out.empty() ? "-" : out;
}

std::string severity_word(const events::Incident& incident) {
    if (incident.uncorrected && incident.context_corrupt) return "FATAL";
    if (incident.uncorrected) return "uncorrected";
    return "corrected";
}

std::string_view severity_colour(const events::Incident& incident, const text::Style& style) {
    if (incident.uncorrected && incident.context_corrupt) return style.bad;
    if (incident.uncorrected) return style.warn;
    return style.good;
}

}  // namespace

std::string incident_table(const std::vector<events::Incident>& incidents,
                           const text::Style& style, const IncidentOptions& options) {
    if (incidents.empty()) {
        return text::paragraph("No WHEA records in the selected range.");
    }

    text::Table table({"#", "When", "Severity", "Cores", "Banks", "Records", "Note"});
    for (std::size_t i = 0; i < incidents.size(); ++i) {
        const events::Incident& incident = incidents[i];

        std::string note;
        if (incident.post_boot_harvest) {
            // Spec §4.5 wants this said explicitly, not implied.
            note = "harvested " + text::format_span(incident.seconds_after_boot) +
                   " after boot - belongs to the previous session";
        } else if (incident.overflow) {
            note = "overflow: earlier errors were lost";
        }

        table.add_row({std::to_string(i + 1), options.time(incident.time), severity_word(incident),
                       join_numbers(incident.apic_ids), join_numbers(incident.banks),
                       std::to_string(incident.records.size()), note});
    }

    std::string out = table.render(style);

    // Spec §6: lead with the conclusion. A count of distinct incidents matters
    // more than a count of records, because a broadcast MCE inflates the
    // latter by the core count.
    std::size_t fatal = 0;
    std::size_t uncorrected = 0;
    for (const events::Incident& incident : incidents) {
        if (incident.uncorrected && incident.context_corrupt) {
            ++fatal;
        } else if (incident.uncorrected) {
            ++uncorrected;
        }
    }

    std::string summary = std::to_string(incidents.size()) +
                          (incidents.size() == 1 ? " incident" : " incidents");
    if (fatal > 0) {
        summary += ", " + std::to_string(fatal) + " unrecoverable with processor context corrupt";
    }
    if (uncorrected > 0) {
        summary += ", " + std::to_string(uncorrected) + " uncorrected";
    }
    summary += ".";

    return text::paragraph(summary) + "\n" + out;
}

std::string incident_detail(const events::Incident& incident, std::size_t index,
                            const text::Style& style, const IncidentOptions& options) {
    std::string out;

    out += text::heading("Incident " + std::to_string(index + 1) + "  -  " +
                             options.time(incident.time),
                         style);
    out += '\n';
    out.append(severity_colour(incident, style));
    out += text::paragraph(incident.headline());
    out.append(style.reset);

    if (incident.post_boot_harvest) {
        out += text::bullet(
            "This record was written " + text::format_span(incident.seconds_after_boot) +
            " after a boot. MCA banks survive a warm reset, so Windows harvested it on the way "
            "up and it almost certainly describes the crash that ended the previous session, "
            "not anything that happened after this boot.");
    }
    if (incident.overflow) {
        out += text::bullet(
            "An overflow bit is set: further errors reached the bank and were lost before "
            "this record was read, so this is a lower bound on what happened.");
    }
    if (incident.records.size() > 1) {
        out += text::bullet(
            "The same error was reported by " + std::to_string(incident.apic_ids.size()) +
            " cores within " + text::format_span(incident.last_time - incident.time) +
            ". An uncorrectable machine check is broadcast to every core, so this is one "
            "event, not " + std::to_string(incident.records.size()) + ".");
    }

    text::KeyValueTable summary;
    summary.add("Reporting APIC IDs", join_numbers(incident.apic_ids));
    summary.add("MCA banks", join_numbers(incident.banks));
    summary.add("Records", std::to_string(incident.records.size()));
    if (!incident.records.empty()) {
        const events::WheaRecord& first = incident.records.front();
        summary.add("Provider event ID", std::to_string(first.event.event_id));
        if (first.error_source.has_value()) {
            summary.add("Error source", std::to_string(*first.error_source));
        }
        if (!first.raw_data.empty()) {
            summary.add("CPER blob", std::to_string(first.raw_data.size()) + " bytes",
                        "decoded from " + first.raw_data_format);
        }
    }
    out += '\n';
    out += summary.render(style);

    for (std::size_t i = 0; i < incident.records.size(); ++i) {
        const events::WheaRecord& record = incident.records[i];

        out += '\n';
        std::string title = "Record " + std::to_string(i + 1);
        if (record.apic_id.has_value()) title += "  -  APIC " + std::to_string(*record.apic_id);
        if (record.mca_bank.has_value()) title += ", bank " + std::to_string(*record.mca_bank);
        out += text::heading(title, style);

        text::KeyValueTable fields;
        const auto add_optional = [&](const char* name, const std::optional<unsigned>& value) {
            if (value.has_value()) fields.add(name, std::to_string(*value));
        };
        fields.add("Logged", options.time(record.event.time));
        add_optional("Error type", record.error_type);
        add_optional("Transaction type", record.transaction_type);
        add_optional("Participation", record.participation);
        add_optional("Request type", record.request_type);
        add_optional("Memory or I/O", record.memory_io);
        add_optional("Memory hierarchy level", record.mem_hierarchy_level);
        add_optional("Timeout", record.timeout);
        add_optional("Operation type", record.operation_type);
        add_optional("Channel", record.channel);
        if (!fields.empty()) out += fields.render(style);

        // Spec §6: always show the raw hex beside the interpretation.
        if (record.status.has_value()) {
            out += '\n';
            out += status_text(*record.status, style);
        }
        if (record.address.has_value()) {
            out += '\n';
            out += address_text(*record.address, style);
        }
        if (record.misc.has_value()) {
            out += '\n';
            out += misc_text(*record.misc, style);
        }
        if (record.cper.has_value()) {
            out += '\n';
            out += record_text(*record.cper, style, Options{options.verbose});

            // The same fault is described twice: once by MCA_STATUS from the
            // event's own fields, and once by the check structures inside the
            // CPER blob. Firmware does not always fill both consistently, and
            // two contradictory verdicts next to each other is worse than
            // either - so when they disagree, say which is which.
            if (record.status.has_value()) {
                std::optional<bool> cper_context_corrupt;
                std::optional<bool> cper_uncorrected;
                for (const cper::Section& section : record.cper->sections) {
                    if (!section.ia32_x64.has_value()) continue;
                    for (const auto& info : section.ia32_x64->error_info) {
                        if (!info.check.has_value()) continue;
                        if (info.check->processor_context_corrupt.has_value()) {
                            cper_context_corrupt =
                                cper_context_corrupt.value_or(false) ||
                                *info.check->processor_context_corrupt;
                        }
                        if (info.check->uncorrected.has_value()) {
                            cper_uncorrected = cper_uncorrected.value_or(false) ||
                                               *info.check->uncorrected;
                        }
                    }
                }

                if (cper_context_corrupt.has_value() &&
                    *cper_context_corrupt != record.status->flags.context_corrupt) {
                    out += text::bullet(
                        std::string("MCA_STATUS reports processor context corrupt = ") +
                        (record.status->flags.context_corrupt ? "1" : "0") +
                        ", but the CPER cache-check structure reports " +
                        (*cper_context_corrupt ? "1" : "0") +
                        ". These describe the same fault and should agree. MCA_STATUS is the "
                        "register the CPU actually latched, so trust it over the firmware's "
                        "summary; the disagreement itself is a firmware quirk, not evidence "
                        "about the fault.");
                }
                if (cper_uncorrected.has_value() &&
                    *cper_uncorrected != record.status->flags.uncorrected) {
                    out += text::bullet(
                        "MCA_STATUS and the CPER check structure disagree about whether the "
                        "error was corrected; MCA_STATUS is the authoritative one.");
                }
            }
        }
        if (options.verbose && !record.event.xml.empty()) {
            out += '\n';
            out += text::paragraph("Event XML:");
            out.append(style.dim);
            out += record.event.xml;
            out.append(style.reset);
            out += '\n';
        }
    }

    return out;
}

void incident_json(const events::Incident& incident, json::Writer& writer,
                   bool include_decodes) {
    writer.begin_object();
    writer.member_int("time_unix", incident.time);
    writer.member("time_utc", text::format_utc(incident.time));
    writer.member_int("last_time_unix", incident.last_time);
    writer.member("headline", incident.headline());
    writer.member_bool("uncorrected", incident.uncorrected);
    writer.member_bool("context_corrupt", incident.context_corrupt);
    writer.member_bool("overflow", incident.overflow);
    writer.member_bool("post_boot_harvest", incident.post_boot_harvest);
    writer.member_int("seconds_after_boot", incident.seconds_after_boot);

    writer.key("apic_ids").begin_array();
    for (const unsigned id : incident.apic_ids) writer.value_uint(id);
    writer.end_array();

    writer.key("banks").begin_array();
    for (const unsigned bank : incident.banks) writer.value_uint(bank);
    writer.end_array();

    writer.key("records").begin_array();
    for (const events::WheaRecord& record : incident.records) {
        writer.begin_object();
        writer.member_int("time_unix", record.event.time);
        writer.member("time_utc", text::format_utc(record.event.time));
        writer.member_uint("event_id", record.event.event_id);
        writer.member_uint("record_id", record.event.record_id);

        const auto optional_uint = [&](std::string_view name,
                                       const std::optional<unsigned>& value) {
            if (value.has_value()) {
                writer.member_uint(name, *value);
            } else {
                writer.member_null(name);
            }
        };
        const auto optional_hex = [&](std::string_view name,
                                      const std::optional<std::uint64_t>& value) {
            if (value.has_value()) {
                writer.member_hex(name, *value, 16);
            } else {
                writer.member_null(name);
            }
        };
        optional_uint("error_source", record.error_source);
        optional_uint("apic_id", record.apic_id);
        optional_uint("mca_bank", record.mca_bank);
        optional_hex("mci_stat", record.mci_stat);
        optional_hex("mci_addr", record.mci_addr);
        optional_hex("mci_misc", record.mci_misc);
        optional_uint("error_type", record.error_type);
        optional_uint("transaction_type", record.transaction_type);
        writer.member_uint("raw_data_bytes", record.raw_data.size());

        if (include_decodes) {
            if (record.status.has_value()) {
                writer.key("mca_status");
                status_json(*record.status, writer);
            }
            if (record.address.has_value()) {
                writer.key("mca_addr");
                address_json(*record.address, writer);
            }
            if (record.misc.has_value()) {
                writer.key("mca_misc");
                misc_json(*record.misc, writer);
            }
            if (record.cper.has_value()) {
                writer.key("cper");
                record_json(*record.cper, writer);
            }
        }
        writer.end_object();
    }
    writer.end_array();
    writer.end_object();
}

}  // namespace postmortem::render
