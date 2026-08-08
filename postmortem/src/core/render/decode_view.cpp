#include "core/render/decode_view.hpp"

#include "core/text/format.hpp"

namespace postmortem::render {
namespace {

using text::Table;
using text::to_hex;

std::string to_binary(std::uint64_t value, int width) {
    std::string out = "0b";
    for (int shift = width - 1; shift >= 0; --shift) {
        out += ((value >> shift) & 1u) != 0 ? '1' : '0';
    }
    return out;
}

// Section title plus a blank line before it, so blocks stay separated without
// every caller remembering to add one.
std::string block(std::string_view title, const text::Style& style) {
    return "\n" + text::heading(title, style);
}

void append_bit_table(std::string& out, const std::vector<mca::BitRow>& bits,
                      const text::Style& style) {
    if (bits.empty()) return;

    Table table({"Bit", "Name", "Value", "Meaning"});
    for (const mca::BitRow& row : bits) {
        table.add_row({std::to_string(row.position), std::string(row.name),
                       row.value ? "1" : "0", row.meaning});
    }
    out += table.render(style);
}

void append_field_table(std::string& out, const std::vector<mca::FieldRow>& fields,
                        const text::Style& style) {
    if (fields.empty()) return;

    Table table({"Field", "Value", "Meaning"});
    for (const mca::FieldRow& row : fields) {
        table.add_row({row.name, format_field_value(row), row.meaning});
    }
    out += table.render(style);
}

void append_notes(std::string& out, std::string_view title,
                  const std::vector<std::string>& notes, const text::Style& style) {
    if (notes.empty()) return;
    out += block(title, style);
    for (const std::string& note : notes) out += text::bullet(note);
}

void append_caveats(std::string& out, const std::vector<std::string>& caveats,
                    const text::Style& style) {
    // Spec §6: "Where the tool is uncertain [...] say so explicitly."
    append_notes(out, "Uncertain", caveats, style);
}

void json_bits(json::Writer& writer, std::string_view key,
               const std::vector<mca::BitRow>& bits) {
    writer.key(key).begin_array();
    for (const mca::BitRow& row : bits) {
        writer.begin_object();
        writer.member_int("bit", row.position);
        writer.member("name", row.name);
        writer.member_bool("value", row.value);
        writer.member("meaning", row.meaning);
        writer.end_object();
    }
    writer.end_array();
}

void json_fields(json::Writer& writer, std::string_view key,
                 const std::vector<mca::FieldRow>& fields) {
    writer.key(key).begin_array();
    for (const mca::FieldRow& row : fields) {
        writer.begin_object();
        writer.member("name", row.name);
        writer.member_uint("value", row.value);
        writer.member_int("width_bits", row.width_bits);
        writer.member("meaning", row.meaning);
        writer.end_object();
    }
    writer.end_array();
}

void json_strings(json::Writer& writer, std::string_view key,
                  const std::vector<std::string>& values) {
    writer.key(key).begin_array();
    for (const std::string& value : values) writer.value(value);
    writer.end_array();
}

}  // namespace

// ---------------------------------------------------------------------------
// Walkthrough
// ---------------------------------------------------------------------------

namespace {

constexpr std::size_t kBytesPerLine = 16;

// Hex dump of the lines covering [from, to), with the bytes of the current
// field highlighted and a caret rule underneath.
std::string dump_around(std::span<const std::uint8_t> record, std::size_t offset,
                        std::size_t length, const text::Style& style, std::size_t context_lines) {
    if (record.empty()) return {};

    const std::size_t first_line = (offset / kBytesPerLine);
    const std::size_t last_line = ((offset + (length == 0 ? 1 : length) - 1) / kBytesPerLine);
    const std::size_t start_line = first_line > context_lines ? first_line - context_lines : 0;
    const std::size_t total_lines = (record.size() + kBytesPerLine - 1) / kBytesPerLine;
    const std::size_t end_line = std::min(total_lines, last_line + context_lines + 1);

    std::string out;
    for (std::size_t line = start_line; line < end_line; ++line) {
        const std::size_t base = line * kBytesPerLine;
        const std::size_t count = std::min(kBytesPerLine, record.size() - base);

        std::string address = to_hex(base, 8);
        out += "  ";
        out.append(address.begin() + 2, address.end());
        out += "  ";

        std::string caret = "  ";
        caret.append(8, ' ');
        caret += "  ";

        for (std::size_t i = 0; i < kBytesPerLine; ++i) {
            const std::size_t position = base + i;
            const bool in_field = position >= offset && position < offset + length;
            if (i < count) {
                if (in_field) out.append(style.bad);
                const std::uint8_t byte = record[position];
                static constexpr char kDigits[] = "0123456789ABCDEF";
                out += kDigits[(byte >> 4) & 0xF];
                out += kDigits[byte & 0xF];
                if (in_field) out.append(style.reset);
            } else {
                out += "  ";
            }
            out += ' ';
            caret += in_field ? "^^ " : "   ";
            if (i == 7) {
                out += ' ';
                caret += ' ';
            }
        }

        out += ' ';
        for (std::size_t i = 0; i < count; ++i) {
            const std::uint8_t byte = record[base + i];
            out += (byte >= 0x20 && byte < 0x7F) ? static_cast<char>(byte) : '.';
        }
        out += '\n';

        // Only draw the caret rule under lines that actually contain the
        // field, otherwise it is noise.
        if (line >= first_line && line <= last_line) {
            while (!caret.empty() && caret.back() == ' ') caret.pop_back();
            if (!caret.empty()) {
                out.append(style.bad);
                out += caret;
                out.append(style.reset);
                out += '\n';
            }
        }
    }
    return out;
}

std::string field_heading(const cper::FieldSpan& field) {
    return "+" + to_hex(field.offset, 4) + "  " + field.name + "  (" +
           std::to_string(field.length) + (field.length == 1 ? " byte)" : " bytes)");
}

}  // namespace

std::string walk_frame(std::span<const std::uint8_t> record,
                       const std::vector<cper::FieldSpan>& fields, std::size_t step,
                       const text::Style& style, unsigned rows) {
    std::string out;

    if (fields.empty()) {
        return text::paragraph("There is nothing to walk: the record produced no fields.");
    }
    const std::size_t index = std::min(step, fields.size() - 1);
    const cper::FieldSpan& field = fields[index];

    out += text::heading("Walking the record  -  step " + std::to_string(index + 1) + " of " +
                             std::to_string(fields.size()),
                         style);
    out += '\n';

    // Context lines scale with the window so a tall terminal shows more of the
    // record around the cursor.
    const std::size_t context = rows > 24 ? 3 : 1;
    out += dump_around(record, field.offset, field.length, style, context);
    out += '\n';

    out.append(style.value);
    out += text::paragraph(field_heading(field));
    out.append(style.reset);

    text::KeyValueTable table;
    table.add("Value", field.value.empty() ? "-" : field.value);
    if (!field.meaning.empty()) table.add("Means", field.meaning);
    out += table.render(style, 4);

    if (index + 1 < fields.size()) {
        const cper::FieldSpan& next = fields[index + 1];
        out += '\n';
        out.append(style.dim);
        out += text::paragraph("next: " + field_heading(next));
        out.append(style.reset);
    }

    out += '\n';
    out.append(style.dim);
    out += text::paragraph("space/n step   p back   a auto   g first   G last   q quit");
    out.append(style.reset);
    return out;
}

std::string walk_listing(std::span<const std::uint8_t> record,
                         const std::vector<cper::FieldSpan>& fields, const text::Style& style) {
    std::string out = text::heading("Field-by-field walk of " + std::to_string(record.size()) +
                                        " bytes",
                                    style);
    out += '\n';

    text::Table table({"Offset", "Len", "Field", "Value", "Means"});
    for (const cper::FieldSpan& field : fields) {
        std::string name(static_cast<std::size_t>(field.depth) * 2, ' ');
        name += field.name;
        table.add_row({to_hex(field.offset, 4), std::to_string(field.length), name, field.value,
                       field.meaning});
    }
    out += table.render(style);
    return out;
}

std::string format_field_value(const mca::FieldRow& field) {
    if (field.width_bits > 0 && field.width_bits <= 4) {
        return to_binary(field.value, field.width_bits);
    }
    return to_hex(field.value, (field.width_bits + 3) / 4);
}

// ---------------------------------------------------------------------------
// MCA_STATUS
// ---------------------------------------------------------------------------

std::string status_text(const mca::StatusDecode& decode, const text::Style& style) {
    std::string out;

    out += text::heading("MCA_STATUS  " + to_hex(decode.raw, 16), style);
    out += '\n';

    // Verdict first (spec §6).
    std::string_view verdict_colour = style.value;
    switch (decode.verdict.severity) {
        case mca::Severity::UncorrectedContextCorrupt: verdict_colour = style.bad; break;
        case mca::Severity::UncorrectedRecoverable:    verdict_colour = style.warn; break;
        case mca::Severity::Corrected:                 verdict_colour = style.good; break;
    }
    out.append(verdict_colour);
    out += text::paragraph(decode.verdict.headline);
    out.append(style.reset);

    for (const std::string& note : decode.verdict.notes) out += text::bullet(note);

    out += block("Architectural bits", style);
    append_bit_table(out, decode.architectural_bits, style);

    if (!decode.vendor_bits.empty()) {
        out += block(decode.vendor_bits_are_provisional
                         ? "Vendor-specific bits (AMD SMCA, names provisional)"
                         : "Vendor-specific bits",
                     style);
        append_bit_table(out, decode.vendor_bits, style);
    }

    out += block("Error code  " + to_hex(decode.error_code.raw, 4) + "  " +
                     decode.error_code.summary,
                 style);
    if (!decode.error_code.encoding.empty()) {
        out += text::paragraph("Encoding: " + decode.error_code.encoding);
    }
    if (!decode.error_code.fields.empty()) {
        out += '\n';
        append_field_table(out, decode.error_code.fields, style);
    }

    if (decode.model_specific != 0) {
        out += block("Model-specific error code  " + to_hex(decode.model_specific, 4), style);
        out += text::paragraph(
            "MCA_STATUS[31:16]. Its meaning is defined by the CPU vendor for this family and "
            "is not interpreted here.");
    }

    append_caveats(out, decode.caveats, style);
    return out;
}

void status_json(const mca::StatusDecode& decode, json::Writer& writer) {
    writer.begin_object();
    writer.member_hex("raw", decode.raw, 16);
    writer.member("vendor", cpu::vendor_label(decode.vendor));

    writer.key("flags").begin_object();
    writer.member_bool("valid", decode.flags.valid);
    writer.member_bool("overflow", decode.flags.overflow);
    writer.member_bool("uncorrected", decode.flags.uncorrected);
    writer.member_bool("enabled", decode.flags.enabled);
    writer.member_bool("misc_valid", decode.flags.misc_valid);
    writer.member_bool("address_valid", decode.flags.address_valid);
    writer.member_bool("context_corrupt", decode.flags.context_corrupt);
    writer.end_object();

    json_bits(writer, "architectural_bits", decode.architectural_bits);
    json_bits(writer, "vendor_bits", decode.vendor_bits);
    writer.member_bool("vendor_bits_provisional", decode.vendor_bits_are_provisional);
    writer.member_hex("model_specific", decode.model_specific, 4);

    writer.key("error_code").begin_object();
    writer.member_hex("raw", decode.error_code.raw, 4);
    writer.member("summary", decode.error_code.summary);
    writer.member("encoding", decode.error_code.encoding);
    json_fields(writer, "fields", decode.error_code.fields);
    writer.end_object();

    writer.key("verdict").begin_object();
    writer.member("severity", mca::severity_text(decode.verdict.severity));
    writer.member("headline", decode.verdict.headline);
    json_strings(writer, "notes", decode.verdict.notes);
    writer.end_object();

    json_strings(writer, "caveats", decode.caveats);
    writer.end_object();
}

// ---------------------------------------------------------------------------
// MCA_ADDR
// ---------------------------------------------------------------------------

std::string address_text(const mca::AddressDecode& decode, const text::Style& style) {
    std::string out;

    out += text::heading("MCA_ADDR  " + to_hex(decode.raw, 16), style);
    out += '\n';
    out.append(style.value);
    out += text::paragraph(decode.classification_text);
    out.append(style.reset);
    out += '\n';

    text::KeyValueTable table;
    table.add("Layout", decode.smca_layout ? "AMD SMCA (LSB field + address)" : "flat address",
              decode.smca_layout ? "bits [61:56] are an LSB field, not part of the address"
                                 : "the whole register is the address");
    if (decode.smca_layout) {
        table.add("LSB field [61:56]", std::to_string(decode.lsb_field),
                  decode.lsb_field == 0
                      ? std::string("the whole address is significant")
                      : "the low " + std::to_string(decode.lsb_field) +
                            " bit(s) are not significant");
    }
    table.add("Address bits [55:0]", to_hex(decode.address_bits, 14));
    table.add("Sign-extended", to_hex(decode.sign_extended, 16), "extended from bit 47");
    table.add("Classification", decode.classification_text);
    out += table.render(style);

    append_caveats(out, decode.caveats, style);
    return out;
}

void address_json(const mca::AddressDecode& decode, json::Writer& writer) {
    writer.begin_object();
    writer.member_hex("raw", decode.raw, 16);
    writer.member("vendor", cpu::vendor_label(decode.vendor));
    writer.member_bool("smca_layout", decode.smca_layout);
    writer.member_uint("lsb_field", decode.lsb_field);
    writer.member_uint("insignificant_low_bits", decode.insignificant_low_bits);
    writer.member_hex("address_bits", decode.address_bits, 14);
    writer.member_hex("sign_extended", decode.sign_extended, 16);
    writer.member("classification", decode.classification_text);
    json_strings(writer, "caveats", decode.caveats);
    writer.end_object();
}

// ---------------------------------------------------------------------------
// MCA_MISC
// ---------------------------------------------------------------------------

std::string misc_text(const mca::MiscDecode& decode, const text::Style& style) {
    std::string out;

    out += text::heading("MCA_MISC  " + to_hex(decode.raw, 16), style);
    out += '\n';

    text::KeyValueTable table;
    if (decode.architectural_fields_apply) {
        table.add("Address LSB [5:0]", std::to_string(decode.address_lsb));
        table.add("Address mode [8:6]", std::to_string(decode.address_mode),
                  decode.address_mode_text);
        table.add("Model-specific [63:9]", to_hex(decode.model_specific, 14));
    } else {
        table.add("Model-specific", to_hex(decode.model_specific, 16),
                  "no architectural fields are claimed for this vendor");
    }
    out += table.render(style);

    append_caveats(out, decode.caveats, style);
    return out;
}

void misc_json(const mca::MiscDecode& decode, json::Writer& writer) {
    writer.begin_object();
    writer.member_hex("raw", decode.raw, 16);
    writer.member("vendor", cpu::vendor_label(decode.vendor));
    writer.member_bool("architectural_fields_apply", decode.architectural_fields_apply);
    if (decode.architectural_fields_apply) {
        writer.member_uint("address_lsb", decode.address_lsb);
        writer.member_uint("address_mode", decode.address_mode);
        writer.member("address_mode_text", decode.address_mode_text);
    }
    writer.member_hex("model_specific", decode.model_specific, 16);
    json_strings(writer, "caveats", decode.caveats);
    writer.end_object();
}

// ---------------------------------------------------------------------------
// CPER records
// ---------------------------------------------------------------------------

namespace {

std::string signature_text(const cpu::Signature& signature) {
    return "family " + to_hex(signature.family, 2) + ", model " + to_hex(signature.model, 2) +
           ", stepping " + std::to_string(signature.stepping);
}

void append_check(std::string& out, const cper::CheckInfo& check, const text::Style& style,
                  std::size_t indent) {
    out += text::paragraph(check.kind + " check info: " + to_hex(check.raw, 16) +
                               "  (validation bits " + to_hex(check.validation_bits, 4) + ")",
                           indent);
    if (!check.fields.empty()) {
        out += '\n';
        Table table({"Field", "Value", "Meaning"});
        for (const mca::FieldRow& row : check.fields) {
            table.add_row({row.name, format_field_value(row), row.meaning});
        }
        out += table.render(style, indent);
    }
    if (!check.bits.empty()) {
        out += '\n';
        Table table({"Bit", "Name", "Value", "Meaning"});
        for (const mca::BitRow& row : check.bits) {
            table.add_row({std::to_string(row.position), std::string(row.name),
                           row.value ? "1" : "0", row.meaning});
        }
        out += table.render(style, indent);
    }
    for (const std::string& caveat : check.caveats) out += text::bullet(caveat, indent);
}

void append_ia32_section(std::string& out, const cper::Ia32X64Section& section,
                         const text::Style& style) {
    text::KeyValueTable table;
    if (section.apic_id_valid) {
        table.add("Local APIC ID", std::to_string(section.local_apic_id));
    } else {
        table.add("Local APIC ID", "not reported");
    }
    if (section.signature_valid) {
        table.add("CPU signature", signature_text(section.signature),
                  "from the record's CPUID leaf 1 EAX");
    }
    table.add("Error-info structures",
              std::to_string(section.error_info.size()) + " of " +
                  std::to_string(section.declared_error_info_count) + " declared");
    if (section.declared_context_info_count > 0) {
        table.add("Context-info structures",
                  std::to_string(section.declared_context_info_count) + " declared",
                  "not decoded by this build");
    }
    out += table.render(style, 4);

    for (std::size_t i = 0; i < section.error_info.size(); ++i) {
        const cper::ProcessorErrorInfo& info = section.error_info[i];
        const std::string name = info.check_type_name.empty()
                                     ? to_string(info.check_type)
                                     : info.check_type_name;
        out += '\n';
        out += text::paragraph("Error info " + std::to_string(i) + " - " + name, 4);

        if (info.check.has_value()) {
            out += '\n';
            append_check(out, *info.check, style, 6);
        } else {
            out += text::bullet(
                "the check-info validation bit is clear, or this check-structure GUID is not "
                "one this build decodes; raw value " + to_hex(info.check_info_raw, 16), 6);
        }

        text::KeyValueTable ids;
        if (info.target_id) ids.add("Target ID", to_hex(*info.target_id, 16));
        if (info.requestor_id) ids.add("Requestor ID", to_hex(*info.requestor_id, 16));
        if (info.responder_id) ids.add("Responder ID", to_hex(*info.responder_id, 16));
        if (info.instruction_ip) ids.add("Instruction IP", to_hex(*info.instruction_ip, 16));
        if (!ids.empty()) {
            out += '\n';
            out += ids.render(style, 6);
        }
    }

    for (const std::string& caveat : section.caveats) out += text::bullet(caveat, 4);
}

void append_generic_section(std::string& out, const cper::ProcessorGenericSection& section,
                            const text::Style& style) {
    text::KeyValueTable table;
    if (!section.processor_type_text.empty()) {
        table.add("Processor type", section.processor_type_text);
    }
    if (!section.processor_isa_text.empty()) table.add("ISA", section.processor_isa_text);
    if (!section.error_type_text.empty()) table.add("Error type", section.error_type_text);
    if (!section.operation_text.empty()) table.add("Operation", section.operation_text);
    if (!section.brand_string.empty()) table.add("Brand", section.brand_string);
    if (section.signature_valid) {
        table.add("CPU version", signature_text(section.signature),
                  "CPUID.1 EAX = " + to_hex(section.cpu_version & 0xFFFFFFFFull, 8));
    }
    table.add("Processor ID", std::to_string(section.processor_id), "local APIC ID");
    if (section.instruction_ip != 0) {
        table.add("Instruction IP", to_hex(section.instruction_ip, 16));
    }
    out += table.render(style, 4);
}

void append_memory_section(std::string& out, const cper::PlatformMemorySection& section,
                           const text::Style& style) {
    text::KeyValueTable table;
    const auto add_optional = [&](const char* name, const std::optional<unsigned>& value) {
        if (value.has_value()) table.add(name, std::to_string(*value));
    };

    if (section.physical_address) {
        table.add("Physical address", to_hex(*section.physical_address, 16));
    }
    if (section.physical_address_mask) {
        table.add("Address mask", to_hex(*section.physical_address_mask, 16));
    }
    add_optional("Node", section.node);
    add_optional("Card", section.card);
    add_optional("Module", section.module);
    add_optional("Bank", section.bank);
    add_optional("Device", section.device);
    add_optional("Row", section.row);
    add_optional("Column", section.column);
    add_optional("Rank", section.rank);
    add_optional("Bit position", section.bit_position);
    if (!section.memory_error_type_text.empty()) {
        table.add("Memory error type", section.memory_error_type_text);
    }
    add_optional("SMBIOS card handle", section.card_handle);
    add_optional("SMBIOS module handle", section.module_handle);

    if (table.empty()) {
        out += text::bullet("no field in this section was marked valid", 4);
    } else {
        out += table.render(style, 4);
    }
    for (const std::string& caveat : section.caveats) out += text::bullet(caveat, 4);
}

}  // namespace

std::string record_text(const cper::Record& record, const text::Style& style,
                        const Options& options) {
    std::string out;
    const cper::RecordSummary summary = cper::summarise(record);

    out += text::heading("CPER record", style);
    out += '\n';
    out.append(record.ok ? style.value : style.bad);
    out += text::paragraph(summary.headline);
    out.append(style.reset);
    for (const std::string& note : summary.notes) out += text::bullet(note);

    if (!record.ok) return out;

    out += block("Header", style);
    text::KeyValueTable header;
    header.add("Signature", record.header.signature);
    header.add("Revision", to_hex(record.header.revision, 4));
    header.add("Severity", std::string(cper::severity_text(record.header.severity)),
               "raw " + std::to_string(record.header.severity_raw));
    if (record.header.timestamp_valid && record.header.timestamp.plausible) {
        header.add("Timestamp", record.header.timestamp.to_string(),
                   record.header.timestamp.precise ? "precise" : "not marked precise");
    } else if (record.header.timestamp_valid) {
        header.add("Timestamp", "not decodable",
                   "raw " + to_hex(record.header.timestamp.raw, 16));
    } else {
        header.add("Timestamp", "not present");
    }
    header.add("Record ID", to_hex(record.header.record_id, 16));
    header.add("Record length", std::to_string(record.header.record_length) + " bytes");
    header.add("Sections", std::to_string(record.sections.size()) + " of " +
                               std::to_string(record.header.section_count) + " declared");
    if (record.header.platform_id_valid) {
        header.add("Platform ID", to_string(record.header.platform_id));
    }
    if (record.header.partition_id_valid) {
        header.add("Partition ID", to_string(record.header.partition_id));
    }
    header.add("Creator ID", to_string(record.header.creator_id));
    header.add("Notification", to_string(record.header.notification_type),
               std::string(known_name(record.header.notification_type)));
    out += header.render(style);

    for (std::size_t i = 0; i < record.sections.size(); ++i) {
        const cper::Section& section = record.sections[i];
        const std::string name = section.type_name.empty() ? std::string("unrecognised section")
                                                           : section.type_name;
        out += block("Section " + std::to_string(i) + " - " + name, style);

        text::KeyValueTable descriptor;
        descriptor.add("Type GUID", to_string(section.descriptor.section_type));
        descriptor.add("Severity", std::string(cper::severity_text(section.descriptor.severity)));
        descriptor.add("Extent", std::to_string(section.descriptor.offset) + " + " +
                                     std::to_string(section.descriptor.length) + " bytes");
        if (section.descriptor.fru_text_valid && !section.descriptor.fru_text.empty()) {
            descriptor.add("FRU text", section.descriptor.fru_text);
        }
        if (section.descriptor.fru_id_valid) {
            descriptor.add("FRU ID", to_string(section.descriptor.fru_id));
        }
        if (!section.descriptor.flag_names.empty()) {
            std::string flags;
            for (const std::string& flag : section.descriptor.flag_names) {
                if (!flags.empty()) flags += ", ";
                flags += flag;
            }
            descriptor.add("Flags", flags);
        }
        out += descriptor.render(style, 2);

        if (!section.body_available) {
            for (const std::string& caveat : section.caveats) out += text::bullet(caveat, 2);
            continue;
        }

        out += '\n';
        if (section.processor_generic.has_value()) {
            append_generic_section(out, *section.processor_generic, style);
        } else if (section.ia32_x64.has_value()) {
            append_ia32_section(out, *section.ia32_x64, style);
        } else if (section.platform_memory.has_value()) {
            append_memory_section(out, *section.platform_memory, style);
        }

        for (const std::string& caveat : section.caveats) out += text::bullet(caveat, 2);

        // Spec §4.2 requires the dump for unrecognised sections; --verbose
        // adds it everywhere so a decode can always be checked by hand.
        if (!section.recognised || options.verbose) {
            out += '\n';
            out += text::paragraph("Raw bytes:", 4);
            out.append(style.dim);
            out += section.hex_dump;
            out.append(style.reset);
        }
    }

    return out;
}

void record_json(const cper::Record& record, json::Writer& writer) {
    const cper::RecordSummary summary = cper::summarise(record);

    writer.begin_object();
    writer.member_bool("ok", record.ok);

    writer.key("summary").begin_object();
    writer.member("headline", summary.headline);
    json_strings(writer, "notes", summary.notes);
    writer.end_object();

    json_strings(writer, "errors", record.errors);
    json_strings(writer, "warnings", record.warnings);

    if (!record.ok) {
        writer.end_object();
        return;
    }

    writer.key("header").begin_object();
    writer.member("signature", record.header.signature);
    writer.member_hex("revision", record.header.revision, 4);
    writer.member("severity", cper::severity_text(record.header.severity));
    writer.member_uint("severity_raw", record.header.severity_raw);
    writer.member_uint("section_count", record.header.section_count);
    writer.member_uint("record_length", record.header.record_length);
    writer.member_hex("record_id", record.header.record_id, 16);
    writer.member_hex("flags", record.header.flags, 8);
    writer.key("timestamp").begin_object();
    writer.member_bool("present", record.header.timestamp_valid);
    writer.member_bool("plausible", record.header.timestamp.plausible);
    writer.member_bool("precise", record.header.timestamp.precise);
    writer.member("text", record.header.timestamp.to_string());
    writer.member_hex("raw", record.header.timestamp.raw, 16);
    writer.end_object();
    writer.member("platform_id", to_string(record.header.platform_id));
    writer.member("partition_id", to_string(record.header.partition_id));
    writer.member("creator_id", to_string(record.header.creator_id));
    writer.member("notification_type", to_string(record.header.notification_type));
    writer.end_object();

    writer.key("sections").begin_array();
    for (const cper::Section& section : record.sections) {
        writer.begin_object();
        writer.member("type_guid", to_string(section.descriptor.section_type));
        writer.member("type_name", section.type_name);
        writer.member_bool("recognised", section.recognised);
        writer.member_bool("body_available", section.body_available);
        writer.member_uint("offset", section.descriptor.offset);
        writer.member_uint("length", section.descriptor.length);
        writer.member("severity", cper::severity_text(section.descriptor.severity));
        writer.member("fru_text", section.descriptor.fru_text);
        json_strings(writer, "flags", section.descriptor.flag_names);

        if (section.processor_generic.has_value()) {
            const auto& generic = *section.processor_generic;
            writer.key("processor_generic").begin_object();
            writer.member("processor_type", generic.processor_type_text);
            writer.member("isa", generic.processor_isa_text);
            writer.member("error_type", generic.error_type_text);
            writer.member("operation", generic.operation_text);
            writer.member("brand", generic.brand_string);
            writer.member_hex("cpu_version", generic.cpu_version, 16);
            writer.member_bool("signature_valid", generic.signature_valid);
            writer.member_uint("family", generic.signature.family);
            writer.member_uint("model", generic.signature.model);
            writer.member_uint("stepping", generic.signature.stepping);
            writer.member_uint("processor_id", generic.processor_id);
            writer.end_object();
        }

        if (section.ia32_x64.has_value()) {
            const auto& ia32 = *section.ia32_x64;
            writer.key("ia32_x64").begin_object();
            writer.member_bool("apic_id_valid", ia32.apic_id_valid);
            writer.member_uint("local_apic_id", ia32.local_apic_id);
            writer.member_bool("signature_valid", ia32.signature_valid);
            writer.member_uint("family", ia32.signature.family);
            writer.member_uint("model", ia32.signature.model);
            writer.member_uint("stepping", ia32.signature.stepping);
            writer.member_uint("declared_error_info_count", ia32.declared_error_info_count);
            writer.member_uint("declared_context_info_count", ia32.declared_context_info_count);

            writer.key("error_info").begin_array();
            for (const cper::ProcessorErrorInfo& info : ia32.error_info) {
                writer.begin_object();
                writer.member("check_type_guid", to_string(info.check_type));
                writer.member("check_type_name", info.check_type_name);
                writer.member_hex("check_info_raw", info.check_info_raw, 16);
                if (info.check.has_value()) {
                    writer.key("check").begin_object();
                    writer.member("kind", info.check->kind);
                    writer.member_hex("validation_bits", info.check->validation_bits, 4);
                    json_fields(writer, "fields", info.check->fields);
                    json_bits(writer, "bits", info.check->bits);
                    json_strings(writer, "caveats", info.check->caveats);
                    writer.end_object();
                } else {
                    writer.member_null("check");
                }
                if (info.instruction_ip) {
                    writer.member_hex("instruction_ip", *info.instruction_ip, 16);
                }
                writer.end_object();
            }
            writer.end_array();
            json_strings(writer, "caveats", ia32.caveats);
            writer.end_object();
        }

        if (section.platform_memory.has_value()) {
            const auto& memory = *section.platform_memory;
            writer.key("platform_memory").begin_object();
            const auto optional_uint = [&](std::string_view name,
                                           const std::optional<unsigned>& value) {
                if (value.has_value()) {
                    writer.member_uint(name, *value);
                } else {
                    writer.member_null(name);
                }
            };
            if (memory.physical_address) {
                writer.member_hex("physical_address", *memory.physical_address, 16);
            } else {
                writer.member_null("physical_address");
            }
            optional_uint("node", memory.node);
            optional_uint("card", memory.card);
            optional_uint("module", memory.module);
            optional_uint("bank", memory.bank);
            optional_uint("device", memory.device);
            optional_uint("row", memory.row);
            optional_uint("column", memory.column);
            optional_uint("rank", memory.rank);
            optional_uint("bit_position", memory.bit_position);
            writer.member("memory_error_type", memory.memory_error_type_text);
            optional_uint("smbios_card_handle", memory.card_handle);
            optional_uint("smbios_module_handle", memory.module_handle);
            json_strings(writer, "caveats", memory.caveats);
            writer.end_object();
        }

        json_strings(writer, "caveats", section.caveats);
        writer.end_object();
    }
    writer.end_array();
    writer.end_object();
}

}  // namespace postmortem::render
