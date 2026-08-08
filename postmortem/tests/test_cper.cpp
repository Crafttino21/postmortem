// CPER decoder tests.
//
// No fixture blob ships with the brief, so these build records byte by byte
// from the UEFI Appendix N layouts. That is deliberate: a hand-built record
// states the expected bytes explicitly, so a test failure points at the field
// that moved rather than at an opaque binary.
//
// The last group is the fuzzing §7 asks for, done exhaustively rather than
// randomly: every truncation and a byte-flip sweep over a valid record. The
// parser must produce a diagnostic for each, never a crash or an
// out-of-bounds read.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "check.hpp"
#include "core/cper/guid.hpp"
#include "core/cper/record.hpp"

using postmortem::cper::Guid;
using postmortem::cper::Record;
using postmortem::cper::Severity;

namespace {

void put_u16(std::vector<std::uint8_t>& buffer, std::size_t offset, std::uint16_t value) {
    buffer[offset + 0] = static_cast<std::uint8_t>(value & 0xFF);
    buffer[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
}

void put_u32(std::vector<std::uint8_t>& buffer, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        buffer[offset + i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF);
    }
}

void put_u64(std::vector<std::uint8_t>& buffer, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        buffer[offset + i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF);
    }
}

// EFI_GUID: Data1/2/3 little-endian, Data4 as raw bytes (UEFI Appendix A).
void put_guid(std::vector<std::uint8_t>& buffer, std::size_t offset, const Guid& guid) {
    put_u32(buffer, offset + 0, guid.data1);
    put_u16(buffer, offset + 4, guid.data2);
    put_u16(buffer, offset + 6, guid.data3);
    for (std::size_t i = 0; i < 8; ++i) buffer[offset + 8 + i] = guid.data4[i];
}

constexpr std::size_t kHeaderSize = 128;
constexpr std::size_t kDescriptorSize = 72;
constexpr std::size_t kBodyOffset = kHeaderSize + kDescriptorSize;   // 200
constexpr std::size_t kIa32BodySize = 128;   // fixed part + one error-info structure

// Cache Check info word. Validation bits [7:0] all set; the fields themselves
// live at bit 16 and above, which is the layout spec §4.2 singles out as a
// common source of bugs.
//   transaction type [17:16] = 1 (data access)
//   operation        [19:18] = 3 (data read)
//   level            [23:20] = 2
//   PCC              [24]    = 1
//   uncorrected      [25]    = 1
constexpr std::uint64_t kCacheCheckInfo = 0x032D00FFull;

std::vector<std::uint8_t> build_record(const Guid& section_type,
                                       std::size_t body_size = kIa32BodySize) {
    std::vector<std::uint8_t> buffer(kBodyOffset + body_size, 0);

    // --- Error Record Header, UEFI Table N-1 ---
    buffer[0] = 'C';
    buffer[1] = 'P';
    buffer[2] = 'E';
    buffer[3] = 'R';
    put_u16(buffer, 4, 0x0100);              // revision
    put_u32(buffer, 6, 0xFFFFFFFFu);         // SignatureEnd
    put_u16(buffer, 10, 1);                  // section count
    put_u32(buffer, 12, 1);                  // severity = fatal
    put_u32(buffer, 16, 0x03);               // platform id + timestamp valid
    put_u32(buffer, 20, static_cast<std::uint32_t>(buffer.size()));

    // Timestamp, BCD: 2026-08-08 15:04:21, precise.
    buffer[24] = 0x21;   // seconds
    buffer[25] = 0x04;   // minutes
    buffer[26] = 0x15;   // hours
    buffer[27] = 0x01;   // precise
    buffer[28] = 0x08;   // day
    buffer[29] = 0x08;   // month
    buffer[30] = 0x26;   // year
    buffer[31] = 0x20;   // century

    put_u64(buffer, 96, 0x0123456789ABCDEFull);   // record id

    // --- Section Descriptor, UEFI Table N-2 ---
    put_u32(buffer, kHeaderSize + 0, static_cast<std::uint32_t>(kBodyOffset));
    put_u32(buffer, kHeaderSize + 4, static_cast<std::uint32_t>(body_size));
    put_u16(buffer, kHeaderSize + 8, 0x0100);   // revision
    buffer[kHeaderSize + 10] = 0x03;            // FRU id + FRU text valid
    put_u32(buffer, kHeaderSize + 12, 0x01);    // Primary
    put_guid(buffer, kHeaderSize + 16, section_type);
    put_u32(buffer, kHeaderSize + 48, 1);       // section severity = fatal
    const std::string fru = "CPU0";
    for (std::size_t i = 0; i < fru.size(); ++i) {
        buffer[kHeaderSize + 52 + i] = static_cast<std::uint8_t>(fru[i]);
    }

    return buffer;
}

// Fills the IA32/X64 body: APIC id valid, CPUID valid, one error-info
// structure carrying a Cache Check.
void fill_ia32_body(std::vector<std::uint8_t>& buffer) {
    const std::size_t body = kBodyOffset;

    // bit0 APIC valid, bit1 CPUID valid, error-info count 1 in bits [7:2].
    put_u64(buffer, body + 0, 0x01ull | 0x02ull | (1ull << 2));
    put_u64(buffer, body + 8, 11);   // local APIC id

    // CPUID dump: leaf 1 EAX of a Ryzen 9 5950X.
    put_u32(buffer, body + 16, 0x00A20F12u);

    // Processor Error Info structure, UEFI Table N-9.
    const std::size_t info = body + 64;
    put_guid(buffer, info + 0, postmortem::cper::guids::kCacheCheck);
    put_u64(buffer, info + 16, 0x01ull | (1ull << 4));   // check info + instruction IP valid
    put_u64(buffer, info + 24, kCacheCheckInfo);
    put_u64(buffer, info + 56, 0xFFFFF80012345678ull);   // instruction IP
}

std::vector<std::uint8_t> build_ia32_record() {
    auto buffer = build_record(postmortem::cper::guids::kIa32X64Processor);
    fill_ia32_body(buffer);
    return buffer;
}

const postmortem::mca::FieldRow* find_field(const postmortem::cper::CheckInfo& check,
                                            std::string_view name) {
    for (const auto& row : check.fields) {
        if (row.name == name) return &row;
    }
    return nullptr;
}

const postmortem::mca::BitRow* find_bit(const postmortem::cper::CheckInfo& check,
                                        std::string_view name) {
    for (const auto& row : check.bits) {
        if (row.name == name) return &row;
    }
    return nullptr;
}

}  // namespace

// ---------------------------------------------------------------------------
// GUIDs
// ---------------------------------------------------------------------------

PM_TEST(cper_guid_text_form_round_trips) {
    const std::string text = "9876ccad-47b4-4bdb-b65e-16f193c4f3db";
    const auto parsed = postmortem::cper::parse_guid(text);
    PM_CHECK(parsed.has_value());
    if (!parsed.has_value()) return;

    PM_CHECK(*parsed == postmortem::cper::guids::kProcessorGeneric);
    PM_CHECK_EQ(postmortem::cper::to_string(*parsed), text);

    // Braces are accepted, junk is not.
    PM_CHECK(postmortem::cper::parse_guid("{" + text + "}").has_value());
    PM_CHECK(!postmortem::cper::parse_guid(text + "ff").has_value());
    PM_CHECK(!postmortem::cper::parse_guid("not-a-guid").has_value());
    PM_CHECK(!postmortem::cper::parse_guid("").has_value());
}

PM_TEST(cper_guid_byte_order_is_mixed_endian) {
    // The first three components are little-endian and the last eight bytes
    // are not; reading all sixteen bytes in order would produce a different
    // GUID and dispatch to the wrong section decoder.
    const std::vector<std::uint8_t> bytes{0xad, 0xcc, 0x76, 0x98, 0xb4, 0x47, 0xdb, 0x4b,
                                          0xb6, 0x5e, 0x16, 0xf1, 0x93, 0xc4, 0xf3, 0xdb};
    const auto guid = postmortem::cper::read_guid(bytes);
    PM_CHECK(guid.has_value());
    if (guid.has_value()) {
        PM_CHECK(*guid == postmortem::cper::guids::kProcessorGeneric);
        PM_CHECK_EQ(postmortem::cper::to_string(*guid),
                    std::string("9876ccad-47b4-4bdb-b65e-16f193c4f3db"));
    }

    // Fifteen bytes is not a GUID.
    const std::vector<std::uint8_t> truncated(bytes.begin(), bytes.end() - 1);
    PM_CHECK(!postmortem::cper::read_guid(truncated).has_value());
}

PM_TEST(cper_guid_names_are_only_claimed_for_known_values) {
    PM_CHECK_EQ(postmortem::cper::known_name(postmortem::cper::guids::kCacheCheck),
                std::string_view("Cache Check"));
    PM_CHECK(postmortem::cper::known_name(Guid{}).empty());
}

// ---------------------------------------------------------------------------
// Record header
// ---------------------------------------------------------------------------

PM_TEST(cper_decodes_a_well_formed_header) {
    const auto buffer = build_ia32_record();
    const Record record = postmortem::cper::decode_record(buffer);

    PM_CHECK(record.ok);
    PM_CHECK(record.errors.empty());
    PM_CHECK_EQ(record.header.signature, std::string("CPER"));
    PM_CHECK_EQ(record.header.revision, std::uint16_t{0x0100});
    PM_CHECK_EQ(record.header.section_count, std::uint16_t{1});
    PM_CHECK_EQ(record.header.severity, Severity::Fatal);
    PM_CHECK_EQ(record.header.record_id, 0x0123456789ABCDEFull);
    PM_CHECK(record.header.timestamp_valid);
    PM_CHECK(record.header.timestamp.plausible);
    PM_CHECK(record.header.timestamp.precise);
    PM_CHECK_EQ(record.header.timestamp.to_string(), std::string("2026-08-08 15:04:21"));
    PM_CHECK_EQ(record.sections.size(), std::size_t{1});
}

PM_TEST(cper_rejects_a_buffer_that_is_not_a_record) {
    const std::vector<std::uint8_t> empty;
    const Record from_empty = postmortem::cper::decode_record(empty);
    PM_CHECK(!from_empty.ok);
    PM_CHECK(!from_empty.errors.empty());

    std::vector<std::uint8_t> wrong_signature(200, 0);
    wrong_signature[0] = 'J';
    wrong_signature[1] = 'U';
    wrong_signature[2] = 'N';
    wrong_signature[3] = 'K';
    const Record from_junk = postmortem::cper::decode_record(wrong_signature);
    PM_CHECK(!from_junk.ok);
    PM_CHECK(!from_junk.errors.empty());
}

PM_TEST(cper_warns_about_an_implausible_bcd_timestamp) {
    auto buffer = build_ia32_record();
    buffer[26] = 0x99;   // hours: valid BCD digits, but 99 is not an hour
    const Record record = postmortem::cper::decode_record(buffer);

    PM_CHECK(record.ok);
    PM_CHECK(!record.header.timestamp.plausible);
    PM_CHECK(record.header.timestamp.to_string().empty());
    bool warned = false;
    for (const std::string& warning : record.warnings) {
        if (warning.find("timestamp") != std::string::npos) warned = true;
    }
    PM_CHECK(warned);

    // Non-decimal nibbles are caught too, rather than producing a bogus date.
    auto binary_timestamp = build_ia32_record();
    binary_timestamp[29] = 0x0C;   // month written in binary rather than BCD
    const Record second = postmortem::cper::decode_record(binary_timestamp);
    PM_CHECK(second.ok);
    PM_CHECK(!second.header.timestamp.plausible);
}

PM_TEST(cper_warns_when_the_declared_length_disagrees_with_the_buffer) {
    auto buffer = build_ia32_record();
    put_u32(buffer, 20, 0xFFFF0000u);   // absurd declared length
    const Record record = postmortem::cper::decode_record(buffer);

    PM_CHECK(record.ok);   // still decodable, just inconsistent
    bool warned = false;
    for (const std::string& warning : record.warnings) {
        if (warning.find("record length") != std::string::npos) warned = true;
    }
    PM_CHECK(warned);
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

PM_TEST(cper_decodes_an_ia32_x64_section) {
    const auto buffer = build_ia32_record();
    const Record record = postmortem::cper::decode_record(buffer);
    PM_CHECK_EQ(record.sections.size(), std::size_t{1});
    if (record.sections.empty()) return;

    const auto& section = record.sections.front();
    PM_CHECK(section.recognised);
    PM_CHECK(section.body_available);
    PM_CHECK_EQ(section.type_name, std::string("IA32/X64 Processor Error"));
    PM_CHECK_EQ(section.descriptor.severity, Severity::Fatal);
    PM_CHECK_EQ(section.descriptor.fru_text, std::string("CPU0"));
    PM_CHECK_EQ(section.descriptor.flag_names.size(), std::size_t{1});

    PM_CHECK(section.ia32_x64.has_value());
    if (!section.ia32_x64.has_value()) return;
    const auto& body = *section.ia32_x64;

    PM_CHECK(body.apic_id_valid);
    PM_CHECK_EQ(body.local_apic_id, std::uint64_t{11});

    // Spec §4.2: the error-info count lives in validation bits [7:2].
    PM_CHECK_EQ(body.declared_error_info_count, 1u);
    PM_CHECK_EQ(body.declared_context_info_count, 0u);
    PM_CHECK_EQ(body.error_info.size(), std::size_t{1});

    // The embedded CPUID leaf 1 EAX decodes like a live one.
    PM_CHECK(body.signature_valid);
    PM_CHECK_EQ(body.signature.family, 0x19u);
    PM_CHECK_EQ(body.signature.model, 0x21u);
    PM_CHECK_EQ(body.signature.stepping, 0x2u);
}

PM_TEST(cper_cache_check_fields_start_at_bit_sixteen) {
    // The regression this guards against: reading the fields out of the low
    // half, where the validation bits live. With validation = 0xFF, a decoder
    // that read the transaction type from bits [1:0] would report 3
    // ("reserved") instead of 1 ("Data access") and look plausible doing it.
    const auto buffer = build_ia32_record();
    const Record record = postmortem::cper::decode_record(buffer);
    PM_CHECK_EQ(record.sections.size(), std::size_t{1});
    if (record.sections.empty() || !record.sections.front().ia32_x64.has_value()) return;

    const auto& info = record.sections.front().ia32_x64->error_info;
    PM_CHECK_EQ(info.size(), std::size_t{1});
    if (info.empty()) return;

    PM_CHECK_EQ(info.front().check_type_name, std::string("Cache Check"));
    PM_CHECK(info.front().check.has_value());
    if (!info.front().check.has_value()) return;

    const auto& check = *info.front().check;
    PM_CHECK_EQ(check.kind, std::string("Cache"));
    PM_CHECK_EQ(check.raw, kCacheCheckInfo);
    PM_CHECK_EQ(check.validation_bits, std::uint64_t{0xFF});

    const auto* transaction = find_field(check, "Transaction type");
    PM_CHECK(transaction != nullptr);
    if (transaction != nullptr) {
        PM_CHECK_EQ(transaction->value, std::uint64_t{1});
        PM_CHECK_EQ(transaction->meaning, std::string("Data access"));
    }

    const auto* operation = find_field(check, "Operation");
    PM_CHECK(operation != nullptr);
    if (operation != nullptr) PM_CHECK_EQ(operation->value, std::uint64_t{3});

    const auto* level = find_field(check, "Level");
    PM_CHECK(level != nullptr);
    if (level != nullptr) PM_CHECK_EQ(level->value, std::uint64_t{2});

    const auto* pcc = find_bit(check, "Processor context corrupt");
    PM_CHECK(pcc != nullptr);
    if (pcc != nullptr) {
        PM_CHECK_EQ(pcc->position, 24);
        PM_CHECK(pcc->value);
    }

    const auto* uncorrected = find_bit(check, "Uncorrected");
    PM_CHECK(uncorrected != nullptr);
    if (uncorrected != nullptr) PM_CHECK(uncorrected->value);

    const auto* overflow = find_bit(check, "Overflow");
    PM_CHECK(overflow != nullptr);
    if (overflow != nullptr) PM_CHECK(!overflow->value);

    // The instruction IP was marked valid; the three IDs were not, and must
    // stay absent rather than reading as zero.
    PM_CHECK(info.front().instruction_ip.has_value());
    PM_CHECK(!info.front().target_id.has_value());
    PM_CHECK(!info.front().requestor_id.has_value());
}

PM_TEST(cper_check_fields_are_omitted_when_their_validation_bit_is_clear) {
    auto buffer = build_ia32_record();
    // Clear every validation bit but keep the field bits set.
    put_u64(buffer, kBodyOffset + 64 + 24, kCacheCheckInfo & ~0xFFull);
    const Record record = postmortem::cper::decode_record(buffer);

    PM_CHECK(record.sections.size() == 1 && record.sections.front().ia32_x64.has_value());
    if (record.sections.empty() || !record.sections.front().ia32_x64.has_value()) return;

    const auto& check = record.sections.front().ia32_x64->error_info.front().check;
    PM_CHECK(check.has_value());
    if (!check.has_value()) return;

    PM_CHECK(check->fields.empty());
    PM_CHECK(check->bits.empty());
    PM_CHECK(!check->caveats.empty());   // and it says why
}

PM_TEST(cper_decodes_a_processor_generic_section) {
    auto buffer = build_record(postmortem::cper::guids::kProcessorGeneric, 192);
    const std::size_t body = kBodyOffset;

    // Validation: processor type, ISA, error type, operation, CPU version,
    // brand string.
    put_u64(buffer, body + 0, 0x01ull | 0x02ull | 0x04ull | 0x08ull | (1ull << 6) | (1ull << 7));
    buffer[body + 8] = 0;    // IA32/X64
    buffer[body + 9] = 2;    // X64
    buffer[body + 10] = 1;   // cache error
    buffer[body + 11] = 1;   // data read
    put_u64(buffer, body + 16, 0x00A20F12ull);

    const std::string brand = "AMD Ryzen 9 5950X 16-Core Processor";
    for (std::size_t i = 0; i < brand.size(); ++i) {
        buffer[body + 24 + i] = static_cast<std::uint8_t>(brand[i]);
    }
    put_u64(buffer, body + 152, 5);   // processor id

    const Record record = postmortem::cper::decode_record(buffer);
    PM_CHECK_EQ(record.sections.size(), std::size_t{1});
    if (record.sections.empty()) return;

    const auto& section = record.sections.front();
    PM_CHECK(section.recognised);
    PM_CHECK(section.processor_generic.has_value());
    if (!section.processor_generic.has_value()) return;

    const auto& generic = *section.processor_generic;
    PM_CHECK_EQ(generic.processor_isa_text, std::string("X64"));
    PM_CHECK_EQ(generic.error_type_text, std::string("cache error"));
    PM_CHECK_EQ(generic.brand_string, brand);
    PM_CHECK_EQ(generic.processor_id, std::uint64_t{5});

    // Spec §4.2: CPUVersion decodes as CPUID leaf 1 EAX.
    PM_CHECK(generic.signature_valid);
    PM_CHECK_EQ(generic.signature.family, 0x19u);
    PM_CHECK_EQ(generic.signature.model, 0x21u);
}

PM_TEST(cper_unknown_section_is_dumped_rather_than_dropped) {
    // Spec §4.2: "Unknown section GUIDs: do not fail. Emit the GUID, length,
    // and a hex dump, and carry on."
    const auto vendor_guid = postmortem::cper::parse_guid("11112222-3333-4444-5555-666677778888");
    PM_CHECK(vendor_guid.has_value());
    if (!vendor_guid.has_value()) return;

    auto buffer = build_record(*vendor_guid, 32);
    for (std::size_t i = 0; i < 32; ++i) {
        buffer[kBodyOffset + i] = static_cast<std::uint8_t>(0xA0 + i);
    }

    const Record record = postmortem::cper::decode_record(buffer);
    PM_CHECK(record.ok);
    PM_CHECK(record.errors.empty());
    PM_CHECK_EQ(record.sections.size(), std::size_t{1});
    if (record.sections.empty()) return;

    const auto& section = record.sections.front();
    PM_CHECK(!section.recognised);
    PM_CHECK(section.body_available);
    PM_CHECK(section.type_name.empty());
    PM_CHECK_EQ(section.body_length, std::size_t{32});
    PM_CHECK(!section.hex_dump.empty());
    PM_CHECK(section.hex_dump.find("A0 A1 A2") != std::string::npos);
    PM_CHECK(!section.caveats.empty());
}

// ---------------------------------------------------------------------------
// Malformed input (spec §7: "Malformed input must produce a diagnostic, never
// a crash or an out-of-bounds read.")
// ---------------------------------------------------------------------------

PM_TEST(cper_section_body_outside_the_buffer_is_refused) {
    auto buffer = build_ia32_record();
    put_u32(buffer, kHeaderSize + 0, 0x7FFFFFFFu);   // offset far past the end
    const Record record = postmortem::cper::decode_record(buffer);

    PM_CHECK(record.ok);
    PM_CHECK_EQ(record.sections.size(), std::size_t{1});
    if (record.sections.empty()) return;
    PM_CHECK(!record.sections.front().body_available);
    PM_CHECK(!record.sections.front().caveats.empty());
    PM_CHECK(!record.warnings.empty());
}

PM_TEST(cper_section_length_that_overruns_the_buffer_is_refused) {
    auto buffer = build_ia32_record();
    put_u32(buffer, kHeaderSize + 4, 0xFFFFFFF0u);   // length that would wrap
    const Record record = postmortem::cper::decode_record(buffer);

    PM_CHECK(record.ok);
    PM_CHECK_EQ(record.sections.size(), std::size_t{1});
    if (!record.sections.empty()) PM_CHECK(!record.sections.front().body_available);
}

PM_TEST(cper_absurd_section_count_is_truncated_not_trusted) {
    auto buffer = build_ia32_record();
    put_u16(buffer, 10, 0xFFFF);   // 65535 sections in a 328-byte record
    const Record record = postmortem::cper::decode_record(buffer);

    PM_CHECK(record.ok);
    // Only the descriptors that actually fit may be produced.
    PM_CHECK(record.sections.size() <= 3);
    PM_CHECK(!record.warnings.empty());
}

PM_TEST(cper_error_info_count_larger_than_the_section_is_truncated) {
    auto buffer = build_ia32_record();
    // Claim 63 error-info structures (the maximum bits [7:2] can hold) in a
    // section with room for one.
    put_u64(buffer, kBodyOffset + 0, 0x03ull | (63ull << 2));
    const Record record = postmortem::cper::decode_record(buffer);

    PM_CHECK(record.ok);
    PM_CHECK_EQ(record.sections.size(), std::size_t{1});
    if (record.sections.empty() || !record.sections.front().ia32_x64.has_value()) return;

    const auto& body = *record.sections.front().ia32_x64;
    PM_CHECK_EQ(body.declared_error_info_count, 63u);
    PM_CHECK_EQ(body.error_info.size(), std::size_t{1});   // only one fits
    PM_CHECK(!body.caveats.empty());
}

PM_TEST(cper_survives_every_truncation_of_a_valid_record) {
    // The systematic half of the fuzzing §7 asks for: decode every prefix of a
    // well-formed record. Any out-of-bounds read would fault here.
    const auto full = build_ia32_record();
    for (std::size_t length = 0; length <= full.size(); ++length) {
        const std::vector<std::uint8_t> prefix(full.begin(), full.begin() + length);
        const Record record = postmortem::cper::decode_record(prefix);

        if (length < 128) {
            PM_CHECK(!record.ok);
            PM_CHECK(!record.errors.empty());
        } else {
            // Past the header it must stay decodable and must never claim a
            // section body it could not actually read.
            PM_CHECK(record.ok);
            for (const auto& section : record.sections) {
                if (!section.body_available) continue;
                PM_CHECK(section.body_offset + section.body_length <= length);
            }
        }
    }
}

PM_TEST(cper_survives_a_byte_flip_sweep) {
    // The other half: set each byte of a valid record to 0xFF in turn, which
    // maximises every length, offset and count the parser reads.
    const auto original = build_ia32_record();
    for (std::size_t index = 0; index < original.size(); ++index) {
        auto mutated = original;
        mutated[index] = 0xFF;
        const Record record = postmortem::cper::decode_record(mutated);

        // The only fatal outcome is a broken signature; everything else must
        // degrade into warnings.
        if (index < 4) {
            PM_CHECK(!record.ok);
            continue;
        }
        PM_CHECK(record.ok);
        for (const auto& section : record.sections) {
            if (!section.body_available) continue;
            PM_CHECK(section.body_offset + section.body_length <= mutated.size());
        }
    }
}

PM_TEST(cper_survives_an_all_ones_buffer_with_a_valid_signature) {
    std::vector<std::uint8_t> buffer(512, 0xFF);
    buffer[0] = 'C';
    buffer[1] = 'P';
    buffer[2] = 'E';
    buffer[3] = 'R';

    const Record record = postmortem::cper::decode_record(buffer);
    PM_CHECK(record.ok);
    for (const auto& section : record.sections) {
        PM_CHECK(!section.body_available);   // every offset/length is absurd
    }
}
