#include "core/cper/record.hpp"

#include "core/cper/reader.hpp"
#include "core/text/format.hpp"

namespace postmortem::cper {
namespace {

constexpr std::size_t kHeaderSize = 128;          // UEFI Table N-1
constexpr std::size_t kDescriptorSize = 72;       // UEFI Table N-2
constexpr std::uint32_t kSignatureEnd = 0xFFFFFFFFu;

Severity to_severity(std::uint32_t raw) {
    switch (raw) {
        case 0: return Severity::Recoverable;
        case 1: return Severity::Fatal;
        case 2: return Severity::Corrected;
        case 3: return Severity::Informational;
        default: return Severity::Unknown;
    }
}

// Two BCD digits. Returns nullopt if either nibble is not a decimal digit,
// which is how firmware that writes plain binary here is caught.
std::optional<unsigned> bcd(std::uint8_t byte) {
    const unsigned high = (byte >> 4) & 0xF;
    const unsigned low = byte & 0xF;
    if (high > 9 || low > 9) return std::nullopt;
    return high * 10 + low;
}

Timestamp decode_timestamp(const Reader& reader, std::size_t offset, bool valid_bit) {
    Timestamp timestamp;
    timestamp.present = valid_bit;
    timestamp.raw = reader.value_or(reader.u64(offset), std::uint64_t{0});

    const auto seconds = reader.u8(offset + 0);
    const auto minutes = reader.u8(offset + 1);
    const auto hours = reader.u8(offset + 2);
    const auto precision = reader.u8(offset + 3);
    const auto day = reader.u8(offset + 4);
    const auto month = reader.u8(offset + 5);
    const auto year = reader.u8(offset + 6);
    const auto century = reader.u8(offset + 7);

    if (!seconds || !minutes || !hours || !precision || !day || !month || !year || !century) {
        return timestamp;
    }

    timestamp.precise = (*precision & 0x01u) != 0;

    const auto s = bcd(*seconds);
    const auto mi = bcd(*minutes);
    const auto h = bcd(*hours);
    const auto d = bcd(*day);
    const auto mo = bcd(*month);
    const auto y = bcd(*year);
    const auto c = bcd(*century);
    if (!s || !mi || !h || !d || !mo || !y || !c) return timestamp;

    timestamp.second = *s;
    timestamp.minute = *mi;
    timestamp.hour = *h;
    timestamp.day = *d;
    timestamp.month = *mo;
    timestamp.year = *c * 100 + *y;

    timestamp.plausible = timestamp.second <= 60 && timestamp.minute <= 59 &&
                          timestamp.hour <= 23 && timestamp.day >= 1 && timestamp.day <= 31 &&
                          timestamp.month >= 1 && timestamp.month <= 12 &&
                          timestamp.year >= 1998 && timestamp.year <= 2200;
    return timestamp;
}

// UEFI Table N-2, section descriptor flags.
std::vector<std::string> decode_section_flags(std::uint32_t flags) {
    struct FlagName {
        int bit;
        const char* name;
    };
    static constexpr FlagName kFlags[] = {
        {0, "Primary"},
        {1, "Containment warning"},
        {2, "Reset"},
        {3, "Error threshold exceeded"},
        {4, "Resource not accessible"},
        {5, "Latent error"},
        {6, "Propagated"},
        {7, "Overflow"},
    };

    std::vector<std::string> names;
    for (const FlagName& flag : kFlags) {
        if ((flags & (1u << flag.bit)) != 0) names.emplace_back(flag.name);
    }
    return names;
}

std::optional<SectionDescriptor> decode_descriptor(const Reader& reader, std::size_t offset) {
    if (!reader.has(offset, kDescriptorSize)) return std::nullopt;

    SectionDescriptor descriptor;
    descriptor.offset = reader.value_or(reader.u32(offset + 0), 0u);
    descriptor.length = reader.value_or(reader.u32(offset + 4), 0u);
    descriptor.revision = reader.value_or(reader.u16(offset + 8), std::uint16_t{0});
    descriptor.validation_bits = reader.value_or(reader.u8(offset + 10), std::uint8_t{0});
    descriptor.flags = reader.value_or(reader.u32(offset + 12), 0u);

    if (const auto bytes = reader.bytes(offset + 16, 16)) {
        if (const auto guid = read_guid(*bytes)) descriptor.section_type = *guid;
    }
    if (const auto bytes = reader.bytes(offset + 32, 16)) {
        if (const auto guid = read_guid(*bytes)) descriptor.fru_id = *guid;
    }

    descriptor.severity_raw = reader.value_or(reader.u32(offset + 48), 0u);
    descriptor.severity = to_severity(descriptor.severity_raw);
    descriptor.fru_text = reader.text(offset + 52, 20);

    descriptor.fru_id_valid = (descriptor.validation_bits & 0x01u) != 0;
    descriptor.fru_text_valid = (descriptor.validation_bits & 0x02u) != 0;
    descriptor.flag_names = decode_section_flags(descriptor.flags);

    return descriptor;
}

}  // namespace

std::string_view severity_text(Severity severity) {
    switch (severity) {
        case Severity::Recoverable:   return "recoverable";
        case Severity::Fatal:         return "fatal";
        case Severity::Corrected:     return "corrected";
        case Severity::Informational: return "informational";
        case Severity::Unknown:       break;
    }
    return "unknown severity";
}

std::string Timestamp::to_string() const {
    if (!plausible) return {};

    const auto pad = [](unsigned value, int width) {
        std::string text = std::to_string(value);
        while (static_cast<int>(text.size()) < width) text.insert(text.begin(), '0');
        return text;
    };

    return pad(year, 4) + "-" + pad(month, 2) + "-" + pad(day, 2) + " " + pad(hour, 2) + ":" +
           pad(minute, 2) + ":" + pad(second, 2);
}

Record decode_record(std::span<const std::uint8_t> data) {
    Record record;
    const Reader reader(data);

    if (reader.size() < kHeaderSize) {
        record.errors.push_back("record is " + std::to_string(reader.size()) +
                                " bytes, shorter than the 128-byte CPER header");
        return record;
    }

    RecordHeader& header = record.header;
    header.signature = reader.text(0, 4);
    if (header.signature != "CPER") {
        record.errors.push_back("record does not start with the 'CPER' signature (found \"" +
                                header.signature + "\")");
        return record;
    }

    header.revision = reader.value_or(reader.u16(4), std::uint16_t{0});
    header.signature_end = reader.value_or(reader.u32(6), 0u);
    header.section_count = reader.value_or(reader.u16(10), std::uint16_t{0});
    header.severity_raw = reader.value_or(reader.u32(12), 0u);
    header.severity = to_severity(header.severity_raw);
    header.validation_bits = reader.value_or(reader.u32(16), 0u);
    header.record_length = reader.value_or(reader.u32(20), 0u);

    header.platform_id_valid = (header.validation_bits & 0x01u) != 0;
    header.timestamp_valid = (header.validation_bits & 0x02u) != 0;
    header.partition_id_valid = (header.validation_bits & 0x04u) != 0;

    header.timestamp = decode_timestamp(reader, 24, header.timestamp_valid);

    if (const auto bytes = reader.bytes(32, 16)) {
        if (const auto guid = read_guid(*bytes)) header.platform_id = *guid;
    }
    if (const auto bytes = reader.bytes(48, 16)) {
        if (const auto guid = read_guid(*bytes)) header.partition_id = *guid;
    }
    if (const auto bytes = reader.bytes(64, 16)) {
        if (const auto guid = read_guid(*bytes)) header.creator_id = *guid;
    }
    if (const auto bytes = reader.bytes(80, 16)) {
        if (const auto guid = read_guid(*bytes)) header.notification_type = *guid;
    }

    header.record_id = reader.value_or(reader.u64(96), std::uint64_t{0});
    header.flags = reader.value_or(reader.u32(104), 0u);
    header.persistence_info = reader.value_or(reader.u64(108), std::uint64_t{0});

    record.ok = true;

    if (header.signature_end != kSignatureEnd) {
        record.warnings.push_back("SignatureEnd is " + text::to_hex(header.signature_end, 8) +
                                  " rather than 0xFFFFFFFF; the record may be truncated or "
                                  "not a CPER record after all");
    }
    if (header.record_length != reader.size()) {
        record.warnings.push_back(
            "header declares a record length of " + std::to_string(header.record_length) +
            " bytes but " + std::to_string(reader.size()) +
            " were supplied; decoding uses what was supplied");
    }
    if (header.timestamp_valid && !header.timestamp.plausible) {
        record.warnings.push_back(
            "the header timestamp is marked valid but does not decode as BCD, so it is not "
            "shown; the raw value is " + text::to_hex(header.timestamp.raw, 16));
    }

    // Descriptors form a table immediately after the header. A record that
    // claims more sections than the buffer can hold is truncated, not fatal:
    // decode what is there and say what is missing.
    std::size_t decoded_sections = 0;
    for (std::size_t index = 0; index < header.section_count; ++index) {
        const std::size_t descriptor_offset = kHeaderSize + index * kDescriptorSize;
        const auto descriptor = decode_descriptor(reader, descriptor_offset);
        if (!descriptor.has_value()) {
            record.warnings.push_back(
                "record declares " + std::to_string(header.section_count) +
                " sections but only " + std::to_string(decoded_sections) +
                " descriptors fit inside the buffer; the rest are missing");
            break;
        }

        Section section;
        section.descriptor = *descriptor;
        section.type_name = std::string(known_name(descriptor->section_type));
        section.body_offset = descriptor->offset;
        section.body_length = descriptor->length;

        // The one place an attacker-influenced offset/length pair could walk
        // off the buffer. reader.bytes() is the only way to get at the body,
        // and it refuses when the extent does not fit.
        const auto body = reader.bytes(descriptor->offset, descriptor->length);
        if (!body.has_value()) {
            section.caveats.push_back(
                "the descriptor places this section at offset " +
                std::to_string(descriptor->offset) + " with length " +
                std::to_string(descriptor->length) + ", which does not fit inside the " +
                std::to_string(reader.size()) + "-byte record; the body was not read");
            record.warnings.push_back("section " + std::to_string(index) +
                                      " has an out-of-range body and was skipped");
        } else {
            section.body_available = true;
            decode_section_body(section, *body);
        }

        record.sections.push_back(std::move(section));
        ++decoded_sections;
    }

    if (header.section_count == 0) {
        record.warnings.emplace_back("the record declares no sections");
    }

    return record;
}

RecordSummary summarise(const Record& record) {
    RecordSummary summary;

    if (!record.ok) {
        summary.headline = "this is not a decodable CPER record";
        summary.notes = record.errors;
        return summary;
    }

    bool any_uncorrected = false;
    bool any_context_corrupt = false;
    bool any_overflow = false;
    unsigned unrecognised_sections = 0;

    for (const Section& section : record.sections) {
        if (!section.recognised) ++unrecognised_sections;
        if (!section.ia32_x64.has_value()) continue;

        for (const ProcessorErrorInfo& info : section.ia32_x64->error_info) {
            if (!info.check.has_value()) continue;
            const CheckInfo& check = *info.check;
            if (check.uncorrected.value_or(false)) any_uncorrected = true;
            if (check.processor_context_corrupt.value_or(false)) any_context_corrupt = true;
            if (check.overflow.value_or(false)) any_overflow = true;
        }
    }

    // Same three-way reading as the MCA verdict in §4.3, because it is the
    // same information arriving by a different route.
    if (any_uncorrected && any_context_corrupt) {
        summary.headline =
            "unrecoverable, processor context corrupt; the CPU resets immediately, so no "
            "bugcheck and no crash dump is possible";
    } else if (any_uncorrected) {
        summary.headline =
            "uncorrected but processor context intact; expect bugcheck 0x124 "
            "(WHEA_UNCORRECTABLE_ERROR)";
    } else if (record.header.severity == Severity::Fatal) {
        summary.headline =
            "the record is marked fatal, but no error-check structure reports an uncorrected "
            "error; read the sections below before drawing a conclusion";
    } else {
        summary.headline = std::string("severity ") +
                           std::string(severity_text(record.header.severity)) +
                           "; no uncorrected error-check structure is present";
    }

    if (any_overflow) {
        summary.notes.emplace_back(
            "an error-check structure reports overflow: further errors were lost before this "
            "record was written, so it under-counts what happened");
    }
    if (unrecognised_sections > 0) {
        summary.notes.push_back(
            std::to_string(unrecognised_sections) +
            " section(s) use a GUID this build does not decode; their bytes are dumped so "
            "nothing is hidden, but their contents are not interpreted");
    }
    for (const std::string& warning : record.warnings) summary.notes.push_back(warning);

    return summary;
}

}  // namespace postmortem::cper
