#include "core/mca/registers.hpp"

#include "core/text/format.hpp"

namespace postmortem::mca {
namespace {

bool bit(std::uint64_t value, int position) {
    return ((value >> position) & 1u) != 0;
}

std::uint64_t field(std::uint64_t value, int high, int low) {
    const int width = high - low + 1;
    const std::uint64_t mask = width >= 64 ? ~0ull : ((1ull << width) - 1);
    return (value >> low) & mask;
}

// ---------------------------------------------------------------------------
// Sub-field expansion, Intel SDM Vol. 3B Table 16-9.
// ---------------------------------------------------------------------------

void add_field(std::vector<FieldRow>& rows, std::string name, std::uint64_t value, int width,
               std::string_view meaning) {
    rows.push_back(FieldRow{std::move(name), value, width, std::string(meaning)});
}

// ---------------------------------------------------------------------------
// MCA_STATUS[15:0]
// ---------------------------------------------------------------------------

ErrorCode decode_error_code(std::uint16_t code) {
    ErrorCode result;
    result.raw = code;

    // Simple error codes first: these are exact values, and checking them
    // before the pattern forms keeps 0x0400 from being mistaken for a
    // compound encoding (SDM Table 16-8).
    switch (code) {
        case 0x0000:
            result.kind = ErrorCodeKind::NoError;
            result.summary = "no error";
            result.encoding = "simple";
            return result;
        case 0x0001:
            result.kind = ErrorCodeKind::Unclassified;
            result.summary = "unclassified error";
            result.encoding = "simple";
            return result;
        case 0x0002:
            result.kind = ErrorCodeKind::MicrocodeRomParity;
            result.summary = "microcode ROM parity error";
            result.encoding = "simple";
            return result;
        case 0x0003:
            result.kind = ErrorCodeKind::ExternalError;
            result.summary = "external error";
            result.encoding = "simple";
            return result;
        case 0x0004:
            result.kind = ErrorCodeKind::FrcError;
            result.summary = "functional redundancy check error";
            result.encoding = "simple";
            return result;
        case 0x0005:
            result.kind = ErrorCodeKind::InternalParity;
            result.summary = "internal parity error";
            result.encoding = "simple";
            return result;
        case 0x0006:
            result.kind = ErrorCodeKind::SmmHandlerCodeAccessViolation;
            result.summary = "SMM handler code access violation";
            result.encoding = "simple";
            return result;
        case 0x0400:
            result.kind = ErrorCodeKind::InternalTimer;
            result.summary = "internal timer error";
            result.encoding = "0000 0100 0000 0000";
            return result;
        default:
            break;
    }

    // Internal watchdog / unclassified: 0000 0100 0000 xxxx with a non-zero
    // tail, 0x0400 having been taken above.
    if (field(code, 15, 4) == 0x040) {
        result.kind = ErrorCodeKind::InternalWatchdog;
        result.summary = "internal watchdog or unclassified internal error";
        result.encoding = "0000 0100 0000 xxxx";
        add_field(result.fields, "Internal code", field(code, 3, 0), 4, "vendor-defined");
        return result;
    }

    // Generic cache hierarchy: 0000 0000 0000 11LL
    if (field(code, 15, 4) == 0x000 && field(code, 3, 2) == 0b11) {
        const auto ll = static_cast<unsigned>(field(code, 1, 0));
        result.kind = ErrorCodeKind::GenericCacheHierarchy;
        result.summary = "generic cache hierarchy error";
        result.encoding = "0000 0000 0000 11LL";
        add_field(result.fields, "Cache level (LL)", ll, 2, cache_level_text(ll));
        return result;
    }

    // TLB error: 0000 0000 0001 TTLL
    if (field(code, 15, 4) == 0x001) {
        const auto tt = static_cast<unsigned>(field(code, 3, 2));
        const auto ll = static_cast<unsigned>(field(code, 1, 0));
        result.kind = ErrorCodeKind::TlbError;
        result.summary = "TLB error";
        result.encoding = "0000 0000 0001 TTLL";
        add_field(result.fields, "Transaction type (TT)", tt, 2, transaction_type_text(tt));
        add_field(result.fields, "Cache level (LL)", ll, 2, cache_level_text(ll));
        return result;
    }

    // Memory hierarchy / cache error: 0000 0001 RRRR TTLL
    if (field(code, 15, 8) == 0x01) {
        const auto rrrr = static_cast<unsigned>(field(code, 7, 4));
        const auto tt = static_cast<unsigned>(field(code, 3, 2));
        const auto ll = static_cast<unsigned>(field(code, 1, 0));
        result.kind = ErrorCodeKind::MemoryHierarchy;
        result.summary = "memory hierarchy error";
        result.encoding = "0000 0001 RRRR TTLL";
        add_field(result.fields, "Request (RRRR)", rrrr, 4, request_text(rrrr));
        add_field(result.fields, "Transaction type (TT)", tt, 2, transaction_type_text(tt));
        add_field(result.fields, "Cache level (LL)", ll, 2, cache_level_text(ll));
        return result;
    }

    // Bus and interconnect error: 0000 1PPT RRRR IILL
    if (field(code, 15, 11) == 0b00001) {
        const auto pp = static_cast<unsigned>(field(code, 10, 9));
        const auto timeout = static_cast<unsigned>(field(code, 8, 8));
        const auto rrrr = static_cast<unsigned>(field(code, 7, 4));
        const auto ii = static_cast<unsigned>(field(code, 3, 2));
        const auto ll = static_cast<unsigned>(field(code, 1, 0));
        result.kind = ErrorCodeKind::BusInterconnect;
        result.summary = "bus or interconnect error";
        result.encoding = "0000 1PPT RRRR IILL";
        add_field(result.fields, "Participation (PP)", pp, 2, participation_text(pp));
        add_field(result.fields, "Timeout (T)", timeout, 1,
                  timeout != 0 ? "request timed out" : "no timeout");
        add_field(result.fields, "Request (RRRR)", rrrr, 4, request_text(rrrr));
        add_field(result.fields, "Memory or I/O (II)", ii, 2, memory_io_text(ii));
        add_field(result.fields, "Cache level (LL)", ll, 2, cache_level_text(ll));
        return result;
    }

    result.kind = ErrorCodeKind::Unrecognised;
    result.summary = "unrecognised error code encoding";
    result.encoding = "none matched";
    return result;
}

// ---------------------------------------------------------------------------
// The interpretation layer (spec §4.3).
// ---------------------------------------------------------------------------

Verdict build_verdict(const StatusFlags& flags, const ErrorCode& code) {
    Verdict verdict;

    if (!flags.valid) {
        verdict.severity = Severity::Corrected;
        verdict.headline =
            "MCA_STATUS.Val is clear: this bank holds no valid error record, and nothing "
            "below should be read as evidence";
        return verdict;
    }

    if (flags.uncorrected && flags.context_corrupt) {
        verdict.severity = Severity::UncorrectedContextCorrupt;
        verdict.headline =
            "unrecoverable, processor context corrupt; the CPU resets immediately, so no "
            "bugcheck and no crash dump is possible";
    } else if (flags.uncorrected) {
        verdict.severity = Severity::UncorrectedRecoverable;
        verdict.headline =
            "uncorrected but processor context intact; expect bugcheck 0x124 "
            "(WHEA_UNCORRECTABLE_ERROR)";
    } else {
        verdict.severity = Severity::Corrected;
        verdict.headline = "corrected; logged for trending, no immediate impact";
    }

    if (flags.overflow) {
        verdict.notes.emplace_back(
            "Overflow is set: additional errors reached this bank and were lost before this "
            "one was read, so the incident count here is a lower bound");
    }
    if (!flags.enabled) {
        verdict.notes.emplace_back(
            "Enabled is clear: reporting for this error was not enabled, which makes the "
            "record's provenance unusual - treat with care");
    }
    if (!flags.address_valid) {
        verdict.notes.emplace_back("AddrV is clear: MCA_ADDR does not hold a valid address");
    }
    if (!flags.misc_valid) {
        verdict.notes.emplace_back("MiscV is clear: MCA_MISC does not hold valid information");
    }
    if (code.kind == ErrorCodeKind::Unrecognised) {
        verdict.notes.emplace_back(
            "The error code did not match any encoding this build knows; the raw value is "
            "shown above so it can be checked against the vendor documentation by hand");
    }

    return verdict;
}

}  // namespace

// ---------------------------------------------------------------------------
// Sub-field text (Intel SDM Vol. 3B Table 16-9).
// ---------------------------------------------------------------------------

std::string_view transaction_type_text(unsigned tt) {
    switch (tt) {
        case 0b00: return "Instruction";
        case 0b01: return "Data";
        case 0b10: return "Generic";
        default:   return "reserved";
    }
}

std::string_view cache_level_text(unsigned ll) {
    // Encoding levels are numbered from the core outwards, so LL=0 is the
    // cache nearest the core - conventionally called L1 in product datasheets.
    switch (ll) {
        case 0b00: return "L0 (nearest the core, usually the L1 cache)";
        case 0b01: return "L1 (usually the L2 cache)";
        case 0b10: return "L2 (usually the L3 cache)";
        default:   return "generic / level not specified";
    }
}

std::string_view request_text(unsigned rrrr) {
    switch (rrrr) {
        case 0b0000: return "ERR - generic error, request type not specified";
        case 0b0001: return "RD - generic read";
        case 0b0010: return "WR - generic write";
        case 0b0011: return "DRD - data read";
        case 0b0100: return "DWR - data write";
        case 0b0101: return "IRD - instruction fetch";
        case 0b0110: return "PREFETCH";
        case 0b0111: return "EVICT";
        case 0b1000: return "SNOOP";
        default:     return "reserved";
    }
}

std::string_view participation_text(unsigned pp) {
    switch (pp) {
        case 0b00: return "SRC - this processor originated the request";
        case 0b01: return "RES - this processor responded to the request";
        case 0b10: return "OBS - this processor observed the error as a third party";
        default:   return "generic / participation not specified";
    }
}

std::string_view memory_io_text(unsigned ii) {
    switch (ii) {
        case 0b00: return "M - memory access";
        case 0b01: return "reserved";
        case 0b10: return "IO - I/O access";
        default:   return "other transaction";
    }
}

std::string_view severity_text(Severity severity) {
    switch (severity) {
        case Severity::Corrected:                 return "corrected";
        case Severity::UncorrectedRecoverable:    return "uncorrected";
        case Severity::UncorrectedContextCorrupt: return "uncorrected, context corrupt";
    }
    return "unknown";
}

std::string_view address_class_text(AddressClass value) {
    switch (value) {
        case AddressClass::UserVirtual:     return "user-mode virtual address";
        case AddressClass::KernelVirtual:   return "kernel-mode virtual address";
        case AddressClass::PhysicalOrIndex: return "physical address or structure index";
        case AddressClass::NoAddress:       return "no address reported";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// MCA_STATUS
// ---------------------------------------------------------------------------

StatusDecode decode_status(std::uint64_t value, Vendor vendor) {
    StatusDecode decode;
    decode.raw = value;
    decode.vendor = vendor;

    // Architectural bits, identical on both vendors (SDM Table 16-6).
    StatusFlags& flags = decode.flags;
    flags.valid = bit(value, 63);
    flags.overflow = bit(value, 62);
    flags.uncorrected = bit(value, 61);
    flags.enabled = bit(value, 60);
    flags.misc_valid = bit(value, 59);
    flags.address_valid = bit(value, 58);
    flags.context_corrupt = bit(value, 57);

    decode.architectural_bits = {
        BitRow{63, "Val", flags.valid,
               flags.valid ? "this bank holds a valid error record"
                           : "no valid error record in this bank"},
        BitRow{62, "Overflow", flags.overflow,
               flags.overflow ? "at least one further error was lost before this was read"
                              : "no errors were lost"},
        BitRow{61, "UC", flags.uncorrected,
               flags.uncorrected ? "the error was not corrected by hardware"
                                 : "hardware corrected the error"},
        BitRow{60, "Enabled", flags.enabled,
               flags.enabled ? "reporting was enabled for this error"
                             : "reporting was not enabled for this error"},
        BitRow{59, "MiscV", flags.misc_valid,
               flags.misc_valid ? "MCA_MISC holds valid information"
                                : "MCA_MISC holds nothing usable"},
        BitRow{58, "AddrV", flags.address_valid,
               flags.address_valid ? "MCA_ADDR holds a valid address"
                                   : "MCA_ADDR holds nothing usable"},
        BitRow{57, "PCC", flags.context_corrupt,
               flags.context_corrupt ? "processor context is corrupt; execution cannot resume"
                                     : "processor context survived the error"},
    };

    // MCA_STATUS[56:53]. Spec §4.3 names these Deferred/Poison/TCC/SyndV on
    // AMD SMCA but also says to label them vendor-specific rather than assert
    // a single layout - AMD assigns them per family, so the names below are
    // provisional and the caller is told so.
    if (vendor == Vendor::Amd || vendor == Vendor::Unknown) {
        decode.vendor_bits = {
            BitRow{56, "Deferred?", bit(value, 56), "AMD SMCA vendor-specific status bit"},
            BitRow{55, "Poison?", bit(value, 55), "AMD SMCA vendor-specific status bit"},
            BitRow{54, "TCC?", bit(value, 54), "AMD SMCA vendor-specific status bit"},
            BitRow{53, "SyndV?", bit(value, 53), "AMD SMCA vendor-specific status bit"},
        };
        decode.vendor_bits_are_provisional = true;
        decode.caveats.emplace_back(
            "MCA_STATUS[56:53] is decoded using the SMCA names from the project brief. AMD "
            "assigns these bits per family - check the PPR for this family before relying on "
            "the names; the raw values are correct regardless");
    }

    decode.model_specific = static_cast<std::uint16_t>(field(value, 31, 16));
    decode.error_code = decode_error_code(static_cast<std::uint16_t>(field(value, 15, 0)));
    decode.verdict = build_verdict(flags, decode.error_code);

    if (vendor == Vendor::Unknown) {
        decode.caveats.emplace_back(
            "CPU vendor not supplied, so vendor-specific fields are decoded as AMD SMCA; the "
            "architectural bits [63:57] and the error code [15:0] are vendor-neutral");
    }
    if (decode.model_specific != 0) {
        decode.caveats.emplace_back(
            "MCA_STATUS[31:16] = " + text::to_hex(decode.model_specific, 4) +
            " is a model-specific error code (AMD SMCA places an ExtErrorCode in [21:16]); "
            "this build reports it raw rather than guessing at its meaning");
    }

    return decode;
}

// ---------------------------------------------------------------------------
// MCA_ADDR
// ---------------------------------------------------------------------------

AddressDecode decode_address(std::uint64_t value, Vendor vendor) {
    AddressDecode decode;
    decode.raw = value;
    decode.vendor = vendor;

    // Spec §4.3: on AMD SMCA this register is not a flat address - bits [55:0]
    // hold the address and [61:56] an LSB field naming the least significant
    // valid bit. Intel's IA32_MCi_ADDR is flat, so the split must not be
    // applied there. With the vendor unknown the SMCA reading is the safer
    // default: an Intel address is unaffected whenever [61:56] is zero, and a
    // non-zero [61:56] would make no sense as part of a canonical address.
    decode.smca_layout = vendor != Vendor::Intel;

    if (decode.smca_layout) {
        decode.lsb_field = static_cast<unsigned>(field(value, 61, 56));
        decode.address_bits = field(value, 55, 0);
        decode.insignificant_low_bits = decode.lsb_field;
    } else {
        decode.address_bits = value;
    }

    // Sign-extend from bit 47, the top of a 48-bit x86-64 canonical address.
    constexpr int kCanonicalSignBit = 47;
    const bool negative = bit(decode.address_bits, kCanonicalSignBit);
    const std::uint64_t low_48 = field(decode.address_bits, kCanonicalSignBit, 0);
    decode.sign_extended = negative ? (low_48 | ~((1ull << (kCanonicalSignBit + 1)) - 1)) : low_48;

    // Classification works on the bits *above* 47 as they actually arrived,
    // not on the sign-extended result: sign extension forces canonical form,
    // so testing the extended value would classify everything as a virtual
    // address and never identify a physical one.
    const std::uint64_t upper = decode.smca_layout ? field(decode.address_bits, 55, 48)
                                                   : field(decode.address_bits, 63, 48);
    const std::uint64_t upper_all_ones = decode.smca_layout ? 0xFFull : 0xFFFFull;

    if (decode.address_bits == 0) {
        decode.classification = AddressClass::NoAddress;
    } else if (!negative && upper == 0) {
        decode.classification = AddressClass::UserVirtual;
    } else if (negative && upper == upper_all_ones) {
        decode.classification = AddressClass::KernelVirtual;
    } else {
        decode.classification = AddressClass::PhysicalOrIndex;
    }
    decode.classification_text = std::string(address_class_text(decode.classification));

    if (decode.classification == AddressClass::UserVirtual) {
        decode.caveats.emplace_back(
            "A low canonical value is indistinguishable from a small physical address; the "
            "user-mode reading is the more likely one but is not certain");
    }
    if (decode.lsb_field > 0) {
        decode.caveats.emplace_back(
            "The LSB field reports that the low " + std::to_string(decode.lsb_field) +
            " bit(s) of the address are not significant, so the fault location is a " +
            std::to_string(1ull << decode.lsb_field) + "-byte region rather than one byte");
    }
    if (vendor == Vendor::Unknown) {
        decode.caveats.emplace_back(
            "CPU vendor not supplied; the AMD SMCA layout was assumed. On Intel the whole "
            "register is a flat address and bits [61:56] are part of it");
    }

    return decode;
}

// ---------------------------------------------------------------------------
// MCA_MISC
// ---------------------------------------------------------------------------

MiscDecode decode_misc(std::uint64_t value, Vendor vendor, bool misc_valid) {
    MiscDecode decode;
    decode.raw = value;
    decode.vendor = vendor;

    if (!misc_valid) {
        decode.model_specific = value;
        decode.caveats.emplace_back(
            "MCA_STATUS.MiscV is clear, so this register's contents are not meaningful");
        return decode;
    }

    // Intel SDM Vol. 3B: with MiscV set, IA32_MCi_MISC[5:0] is the recoverable
    // address LSB and [8:6] the address mode. AMD's MCA_MISC0 is laid out per
    // family, and the address-LSB information there already travels in
    // MCA_ADDR[61:56], so nothing is claimed for AMD.
    if (vendor == Vendor::Intel) {
        decode.architectural_fields_apply = true;
        decode.address_lsb = static_cast<unsigned>(field(value, 5, 0));
        decode.address_mode = static_cast<unsigned>(field(value, 8, 6));
        switch (decode.address_mode) {
            case 0: decode.address_mode_text = "segment offset"; break;
            case 1: decode.address_mode_text = "linear address"; break;
            case 2: decode.address_mode_text = "physical address"; break;
            case 3: decode.address_mode_text = "memory address"; break;
            case 7: decode.address_mode_text = "generic"; break;
            default: decode.address_mode_text = "reserved"; break;
        }
        decode.model_specific = field(value, 63, 9);
    } else {
        decode.model_specific = value;
        decode.caveats.emplace_back(
            "MCA_MISC is laid out per family on AMD; this build reports it raw rather than "
            "guessing. The address granularity it would carry is available from "
            "MCA_ADDR[61:56] instead");
    }

    return decode;
}

}  // namespace postmortem::mca
