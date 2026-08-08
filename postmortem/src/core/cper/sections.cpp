// CPER section body decoding (spec §4.2).

#include "core/cper/reader.hpp"
#include "core/cper/record.hpp"
#include "core/text/format.hpp"

namespace postmortem::cper {
namespace {

bool bit(std::uint64_t value, int position) {
    return ((value >> position) & 1u) != 0;
}

std::uint64_t field(std::uint64_t value, int high, int low) {
    const int width = high - low + 1;
    const std::uint64_t mask = width >= 64 ? ~0ull : ((1ull << width) - 1);
    return (value >> low) & mask;
}

void add_field(std::vector<mca::FieldRow>& rows, std::string name, std::uint64_t value, int width,
               std::string_view meaning) {
    rows.push_back(mca::FieldRow{std::move(name), value, width, std::string(meaning)});
}

void add_bit(std::vector<mca::BitRow>& rows, int position, std::string_view name, bool value,
             std::string_view meaning) {
    rows.push_back(mca::BitRow{position, name, value, std::string(meaning)});
}

// ---------------------------------------------------------------------------
// Check structures (UEFI N.2.4.2.x)
//
// Spec §4.2 calls this out as a common source of bugs, and it is: the
// validation bits sit in [7:0] (or [15:0] for the wider structures) while the
// fields themselves start at bit 16. Reading a field from the low half yields
// plausible-looking nonsense, which is exactly the failure mode the tool
// exists to prevent.
// ---------------------------------------------------------------------------

std::string_view check_transaction_type(unsigned value) {
    switch (value) {
        case 0: return "Instruction";
        case 1: return "Data access";
        case 2: return "Generic";
        default: return "reserved";
    }
}

std::string_view cache_tlb_operation(unsigned value) {
    switch (value) {
        case 0: return "generic error";
        case 1: return "generic read";
        case 2: return "generic write";
        case 3: return "data read";
        case 4: return "data write";
        case 5: return "instruction fetch";
        case 6: return "prefetch";
        case 7: return "eviction";
        case 8: return "snoop";
        default: return "reserved";
    }
}

// The five flag bits Cache, TLB and Bus checks all share, at [28:24].
void add_common_check_bits(CheckInfo& info, std::uint64_t value, std::uint64_t validation,
                           int first_validation_bit) {
    struct Flag {
        int validation_bit;
        int field_bit;
        const char* name;
        const char* set_meaning;
        const char* clear_meaning;
    };
    const Flag flags[] = {
        {first_validation_bit + 0, 24, "Processor context corrupt",
         "processor context is corrupt; execution cannot resume", "processor context survived"},
        {first_validation_bit + 1, 25, "Uncorrected", "the error was not corrected",
         "the error was corrected"},
        {first_validation_bit + 2, 26, "Precise IP",
         "the instruction pointer is precise", "the instruction pointer is not precise"},
        {first_validation_bit + 3, 27, "Restartable IP",
         "execution could be restarted at the saved IP", "execution cannot be restarted"},
        {first_validation_bit + 4, 28, "Overflow",
         "a further error was lost before this one was read", "no errors were lost"},
    };

    for (const Flag& flag : flags) {
        if (!bit(validation, flag.validation_bit)) continue;
        const bool set = bit(value, flag.field_bit);
        add_bit(info.bits, flag.field_bit, flag.name, set,
                set ? flag.set_meaning : flag.clear_meaning);

        switch (flag.field_bit) {
            case 24: info.processor_context_corrupt = set; break;
            case 25: info.uncorrected = set; break;
            case 28: info.overflow = set; break;
            default: break;
        }
    }
}

// UEFI N.2.4.2.1 Cache Check and N.2.4.2.2 TLB Check share a layout; the spec
// brief states it explicitly for Cache Check:
//   validation [7:0]; transaction type [17:16]; operation [19:18];
//   level [23:20]; PCC [24]; uncorrected [25]; precise IP [26];
//   restartable IP [27]; overflow [28].
CheckInfo decode_cache_or_tlb_check(std::uint64_t value, bool is_tlb) {
    CheckInfo info;
    info.kind = is_tlb ? "TLB" : "Cache";
    info.raw = value;
    info.validation_bits = field(value, 7, 0);

    if (bit(info.validation_bits, 0)) {
        const auto tt = static_cast<unsigned>(field(value, 17, 16));
        add_field(info.fields, "Transaction type", tt, 2, check_transaction_type(tt));
    }
    if (bit(info.validation_bits, 1)) {
        const auto op = static_cast<unsigned>(field(value, 19, 18));
        add_field(info.fields, "Operation", op, 2, cache_tlb_operation(op));
    }
    if (bit(info.validation_bits, 2)) {
        const auto level = static_cast<unsigned>(field(value, 23, 20));
        add_field(info.fields, "Level", level, 4,
                  "cache/TLB level, counted from the core outwards");
    }

    add_common_check_bits(info, value, info.validation_bits, 3);

    if (info.validation_bits == 0) {
        info.caveats.emplace_back(
            "no validation bits are set, so this check structure carries no usable fields; "
            "the raw value is shown for manual inspection");
    }
    return info;
}

// UEFI N.2.4.2.3 Bus Check. Same first five fields as Cache/TLB, plus
// participation [30:29], timed out [31] and address space [33:32], each with
// its own validation bit above the shared five.
CheckInfo decode_bus_check(std::uint64_t value) {
    CheckInfo info;
    info.kind = "Bus";
    info.raw = value;
    info.validation_bits = field(value, 15, 0);

    if (bit(info.validation_bits, 0)) {
        const auto tt = static_cast<unsigned>(field(value, 17, 16));
        add_field(info.fields, "Transaction type", tt, 2, check_transaction_type(tt));
    }
    if (bit(info.validation_bits, 1)) {
        const auto op = static_cast<unsigned>(field(value, 19, 18));
        add_field(info.fields, "Operation", op, 2, cache_tlb_operation(op));
    }
    if (bit(info.validation_bits, 2)) {
        const auto level = static_cast<unsigned>(field(value, 23, 20));
        add_field(info.fields, "Level", level, 4, "bus hierarchy level");
    }

    add_common_check_bits(info, value, info.validation_bits, 3);

    if (bit(info.validation_bits, 8)) {
        const auto pp = static_cast<unsigned>(field(value, 30, 29));
        add_field(info.fields, "Participation", pp, 2, mca::participation_text(pp));
    }
    if (bit(info.validation_bits, 9)) {
        const bool timed_out = bit(value, 31);
        add_bit(info.bits, 31, "Timed out", timed_out,
                timed_out ? "the request timed out" : "the request did not time out");
    }
    if (bit(info.validation_bits, 10)) {
        const auto space = static_cast<unsigned>(field(value, 33, 32));
        add_field(info.fields, "Address space", space, 2,
                  space == 0 ? "memory" : (space == 2 ? "I/O" : "other"));
    }

    return info;
}

// UEFI N.2.4.2.4 Micro-Architectural (MS) Check. The layout differs from the
// three above: error type at [18:16] and the flags shifted down accordingly.
CheckInfo decode_ms_check(std::uint64_t value) {
    CheckInfo info;
    info.kind = "Micro-Architectural";
    info.raw = value;
    info.validation_bits = field(value, 15, 0);

    if (bit(info.validation_bits, 0)) {
        const auto type = static_cast<unsigned>(field(value, 18, 16));
        std::string_view meaning;
        switch (type) {
            case 0: meaning = "no error"; break;
            case 1: meaning = "unclassified"; break;
            case 2: meaning = "microcode ROM parity error"; break;
            case 3: meaning = "external error"; break;
            case 4: meaning = "FRC error"; break;
            case 5: meaning = "internal unclassified"; break;
            default: meaning = "reserved"; break;
        }
        add_field(info.fields, "Error type", type, 3, meaning);
    }

    struct Flag {
        int validation_bit;
        int field_bit;
        const char* name;
    };
    static constexpr Flag kFlags[] = {
        {1, 19, "Processor context corrupt"},
        {2, 20, "Uncorrected"},
        {3, 21, "Precise IP"},
        {4, 22, "Restartable IP"},
        {5, 23, "Overflow"},
    };
    for (const Flag& flag : kFlags) {
        if (!bit(info.validation_bits, flag.validation_bit)) continue;
        const bool set = bit(value, flag.field_bit);
        add_bit(info.bits, flag.field_bit, flag.name, set, set ? "set" : "clear");

        switch (flag.field_bit) {
            case 19: info.processor_context_corrupt = set; break;
            case 20: info.uncorrected = set; break;
            case 23: info.overflow = set; break;
            default: break;
        }
    }

    info.caveats.emplace_back(
        "the Micro-Architectural check layout places its fields at [23:16] rather than the "
        "[28:16] used by the cache, TLB and bus checks; verify against UEFI N.2.4.2.4 before "
        "relying on these field positions");
    return info;
}

std::optional<CheckInfo> decode_check_info(const Guid& check_type, std::uint64_t value) {
    if (check_type == guids::kCacheCheck) return decode_cache_or_tlb_check(value, false);
    if (check_type == guids::kTlbCheck) return decode_cache_or_tlb_check(value, true);
    if (check_type == guids::kBusCheck) return decode_bus_check(value);
    if (check_type == guids::kMicroArchitecturalCheck) return decode_ms_check(value);
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Processor Generic (UEFI N.2.4.1)
// ---------------------------------------------------------------------------

std::string_view processor_type_text(std::uint8_t value) {
    switch (value) {
        case 0: return "IA32/X64";
        case 1: return "IA64";
        case 2: return "ARM";
        default: return "unknown processor type";
    }
}

std::string_view processor_isa_text(std::uint8_t value) {
    switch (value) {
        case 0: return "IA32";
        case 1: return "IA64";
        case 2: return "X64";
        case 3: return "ARM A32/T32";
        case 4: return "ARM A64";
        default: return "unknown ISA";
    }
}

std::string_view generic_error_type_text(std::uint8_t value) {
    switch (value) {
        case 0: return "unknown";
        case 1: return "cache error";
        case 2: return "TLB error";
        case 4: return "bus error";
        case 8: return "micro-architectural error";
        default: return "unrecognised error type";
    }
}

std::string_view generic_operation_text(std::uint8_t value) {
    switch (value) {
        case 0: return "generic";
        case 1: return "data read";
        case 2: return "data write";
        case 3: return "instruction execution";
        default: return "unrecognised operation";
    }
}

ProcessorGenericSection decode_processor_generic(std::span<const std::uint8_t> body) {
    const Reader reader(body);
    ProcessorGenericSection section;

    section.validation_bits = reader.value_or(reader.u64(0), std::uint64_t{0});
    const std::uint64_t valid = section.validation_bits;

    section.processor_type = reader.value_or(reader.u8(8), std::uint8_t{0});
    section.processor_isa = reader.value_or(reader.u8(9), std::uint8_t{0});
    section.error_type = reader.value_or(reader.u8(10), std::uint8_t{0});
    section.operation = reader.value_or(reader.u8(11), std::uint8_t{0});
    section.flags = reader.value_or(reader.u8(12), std::uint8_t{0});
    section.level = reader.value_or(reader.u8(13), std::uint8_t{0});
    section.cpu_version = reader.value_or(reader.u64(16), std::uint64_t{0});

    if (bit(valid, 0)) section.processor_type_text = processor_type_text(section.processor_type);
    if (bit(valid, 1)) section.processor_isa_text = processor_isa_text(section.processor_isa);
    if (bit(valid, 2)) section.error_type_text = generic_error_type_text(section.error_type);
    if (bit(valid, 3)) section.operation_text = generic_operation_text(section.operation);

    // Spec §4.2: CPUVersion is CPUID leaf 1 EAX, so it decodes with the same
    // extended-family/extended-model arithmetic as a live CPUID read. The
    // vendor is not carried in the record, so the Intel rule is used - it is
    // the more permissive of the two and only differs for base family 06h.
    if (bit(valid, 6) && section.cpu_version != 0) {
        section.signature_valid = true;
        section.signature = cpu::decode_signature(
            static_cast<std::uint32_t>(section.cpu_version & 0xFFFFFFFFull), cpu::Vendor::Unknown);
    }

    if (bit(valid, 7)) section.brand_string = reader.text(24, 128);

    section.processor_id = reader.value_or(reader.u64(152), std::uint64_t{0});
    section.target_address = reader.value_or(reader.u64(160), std::uint64_t{0});
    section.requestor_id = reader.value_or(reader.u64(168), std::uint64_t{0});
    section.responder_id = reader.value_or(reader.u64(176), std::uint64_t{0});
    section.instruction_ip = reader.value_or(reader.u64(184), std::uint64_t{0});

    return section;
}

// ---------------------------------------------------------------------------
// IA32/X64 Processor Error (UEFI N.2.4.2)
// ---------------------------------------------------------------------------

constexpr std::size_t kErrorInfoSize = 64;   // UEFI Table N-9
constexpr std::size_t kErrorInfoStart = 64;  // after validation, APIC id, CPUID dump

ProcessorErrorInfo decode_error_info(const Reader& reader, std::size_t offset) {
    ProcessorErrorInfo info;

    if (const auto bytes = reader.bytes(offset, 16)) {
        if (const auto guid = read_guid(*bytes)) info.check_type = *guid;
    }
    info.check_type_name = std::string(known_name(info.check_type));

    info.validation_bits = reader.value_or(reader.u64(offset + 16), std::uint64_t{0});
    info.check_info_raw = reader.value_or(reader.u64(offset + 24), std::uint64_t{0});

    // Validation bit 0 gates the check info; the rest gate the four IDs.
    if (bit(info.validation_bits, 0)) {
        info.check = decode_check_info(info.check_type, info.check_info_raw);
    }
    if (bit(info.validation_bits, 1)) info.target_id = reader.u64(offset + 32);
    if (bit(info.validation_bits, 2)) info.requestor_id = reader.u64(offset + 40);
    if (bit(info.validation_bits, 3)) info.responder_id = reader.u64(offset + 48);
    if (bit(info.validation_bits, 4)) info.instruction_ip = reader.u64(offset + 56);

    return info;
}

Ia32X64Section decode_ia32_x64(std::span<const std::uint8_t> body) {
    const Reader reader(body);
    Ia32X64Section section;

    section.validation_bits = reader.value_or(reader.u64(0), std::uint64_t{0});
    section.apic_id_valid = bit(section.validation_bits, 0);
    section.cpuid_info_valid = bit(section.validation_bits, 1);

    // Spec §4.2: the counts are packed into the validation bitmap rather than
    // stored as their own fields.
    section.declared_error_info_count =
        static_cast<unsigned>(field(section.validation_bits, 7, 2));
    section.declared_context_info_count =
        static_cast<unsigned>(field(section.validation_bits, 13, 8));

    section.local_apic_id = reader.value_or(reader.u64(8), std::uint64_t{0});

    if (const auto cpuid = reader.bytes(16, 48)) {
        section.cpuid_info.assign(cpuid->begin(), cpuid->end());
        if (section.cpuid_info_valid) {
            const std::uint32_t eax = static_cast<std::uint32_t>((*cpuid)[0]) |
                                      (static_cast<std::uint32_t>((*cpuid)[1]) << 8) |
                                      (static_cast<std::uint32_t>((*cpuid)[2]) << 16) |
                                      (static_cast<std::uint32_t>((*cpuid)[3]) << 24);
            if (eax != 0) {
                section.signature_valid = true;
                section.signature = cpu::decode_signature(eax, cpu::Vendor::Unknown);
            }
        }
    } else {
        section.caveats.emplace_back(
            "the section is too short to contain the 48-byte CPUID dump");
    }

    for (unsigned index = 0; index < section.declared_error_info_count; ++index) {
        const std::size_t offset = kErrorInfoStart + index * kErrorInfoSize;
        if (!reader.has(offset, kErrorInfoSize)) {
            section.caveats.push_back(
                "the validation bits declare " +
                std::to_string(section.declared_error_info_count) +
                " error-info structures but only " + std::to_string(index) +
                " fit inside the section; the rest were not read");
            break;
        }
        section.error_info.push_back(decode_error_info(reader, offset));
    }

    if (section.declared_context_info_count > 0) {
        section.caveats.push_back(
            "the section declares " + std::to_string(section.declared_context_info_count) +
            " processor context-info structures; this build does not decode them yet and "
            "they are not shown");
    }

    return section;
}

// ---------------------------------------------------------------------------
// Platform Memory Error (UEFI N.2.5)
// ---------------------------------------------------------------------------

std::string_view memory_error_type_text(unsigned value) {
    switch (value) {
        case 0:  return "unknown";
        case 1:  return "no error";
        case 2:  return "single-bit ECC";
        case 3:  return "multi-bit ECC";
        case 4:  return "single-symbol ChipKill ECC";
        case 5:  return "multi-symbol ChipKill ECC";
        case 6:  return "master abort";
        case 7:  return "target abort";
        case 8:  return "parity error";
        case 9:  return "watchdog timeout";
        case 10: return "invalid address";
        case 11: return "mirror broken";
        case 12: return "memory sparing";
        case 13: return "scrub corrected";
        case 14: return "scrub uncorrected";
        case 15: return "physical memory map-out event";
        default: return "unrecognised memory error type";
    }
}

PlatformMemorySection decode_platform_memory(std::span<const std::uint8_t> body) {
    const Reader reader(body);
    PlatformMemorySection section;

    section.validation_bits = reader.value_or(reader.u64(0), std::uint64_t{0});
    const std::uint64_t valid = section.validation_bits;

    const auto u16_if = [&](int validation_bit, std::size_t offset) -> std::optional<unsigned> {
        if (!bit(valid, validation_bit)) return std::nullopt;
        const auto value = reader.u16(offset);
        if (!value.has_value()) return std::nullopt;
        return static_cast<unsigned>(*value);
    };
    const auto u64_if = [&](int validation_bit, std::size_t offset) -> std::optional<std::uint64_t> {
        if (!bit(valid, validation_bit)) return std::nullopt;
        return reader.u64(offset);
    };

    section.error_status = u64_if(0, 8);
    section.physical_address = u64_if(1, 16);
    section.physical_address_mask = u64_if(2, 24);
    section.node = u16_if(3, 32);
    section.card = u16_if(4, 34);
    section.module = u16_if(5, 36);
    section.bank = u16_if(6, 38);
    section.device = u16_if(7, 40);
    section.row = u16_if(8, 42);
    section.column = u16_if(9, 44);
    section.bit_position = u16_if(10, 46);
    section.requestor_id = u64_if(11, 48);
    section.responder_id = u64_if(12, 56);
    section.target_id = u64_if(13, 64);

    if (bit(valid, 14)) {
        if (const auto value = reader.u8(72)) {
            section.memory_error_type = *value;
            section.memory_error_type_text = memory_error_type_text(*value);
        }
    }
    section.rank = u16_if(15, 74);
    section.card_handle = u16_if(16, 76);
    section.module_handle = u16_if(17, 78);

    if (section.card_handle.has_value() || section.module_handle.has_value()) {
        section.caveats.emplace_back(
            "the SMBIOS handles above identify the failing DIMM, but turning them into a slot "
            "label needs the machine's SMBIOS table and is therefore only possible when "
            "running on the affected machine");
    }

    return section;
}

}  // namespace

void decode_section_body(Section& section, std::span<const std::uint8_t> body) {
    const Guid& type = section.descriptor.section_type;

    if (type == guids::kProcessorGeneric) {
        section.recognised = true;
        section.processor_generic = decode_processor_generic(body);
    } else if (type == guids::kIa32X64Processor) {
        section.recognised = true;
        section.ia32_x64 = decode_ia32_x64(body);
    } else if (type == guids::kPlatformMemory) {
        section.recognised = true;
        section.platform_memory = decode_platform_memory(body);
    } else {
        // Spec §4.2: unknown section GUIDs must not fail the decode. Real
        // records carry vendor and Microsoft-private sections, and dropping
        // them would hide evidence.
        section.recognised = false;
        section.caveats.push_back(
            "section type " + to_string(type) +
            " is not one this build decodes; its " + std::to_string(body.size()) +
            " bytes are dumped verbatim so they can be examined by hand");
    }

    // The raw bytes are kept for every section, recognised or not: spec §6
    // requires the raw value to stay visible next to the interpretation so a
    // reader can re-verify the decode independently.
    section.hex_dump = text::hex_dump(body, section.body_offset);
}

}  // namespace postmortem::cper
