// Machine-check architecture register decoding (spec §4.3).
//
// This is the highest-value module in the tool: WHEA already captured the
// register contents at fault time, so no MSR read - and therefore no kernel
// driver (spec §2) - is needed. Everything here is a pure function of one or
// two 64-bit values, which is why it lives in core/ and is unit-tested against
// the §7 vectors from a real Ryzen 9 5950X.
//
// Spec references, to be checked against when reading this code:
//   Intel SDM Vol. 3B ch. 16 "Machine-Check Architecture":
//     Table 16-8  IA32_MCi_STATUS simple error code encodings
//     Table 16-9  IA32_MCi_STATUS compound error code encodings
//     Table 16-6  IA32_MCi_STATUS bit definitions
//   AMD PPR / APM Vol. 2 ch. 9 for the SMCA (Scalable MCA) additions.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/cpu/signature.hpp"

namespace postmortem::mca {

using cpu::Vendor;

// One decoded bit, rendered by §6's aligned bit-position/name/value/meaning
// table. `meaning` describes what this bit's *current* value implies, not what
// the bit is for in the abstract.
struct BitRow {
    int position = 0;
    std::string_view name;
    bool value = false;
    std::string meaning;
};

// One decoded multi-bit field, e.g. "Transaction type  10b  Generic".
struct FieldRow {
    std::string name;
    std::uint64_t value = 0;
    int width_bits = 0;
    std::string meaning;
};

// ---------------------------------------------------------------------------
// MCA_STATUS
// ---------------------------------------------------------------------------

// The architectural flags in MCA_STATUS[63:57]. Identical on both vendors.
struct StatusFlags {
    bool valid = false;            // [63] Val
    bool overflow = false;         // [62] Overflow
    bool uncorrected = false;      // [61] UC
    bool enabled = false;          // [60] Enabled
    bool misc_valid = false;       // [59] MiscV
    bool address_valid = false;    // [58] AddrV
    bool context_corrupt = false;  // [57] PCC
};

enum class ErrorCodeKind {
    NoError,
    Unclassified,
    MicrocodeRomParity,
    ExternalError,
    FrcError,
    InternalParity,
    SmmHandlerCodeAccessViolation,
    InternalTimer,
    InternalWatchdog,
    GenericCacheHierarchy,
    TlbError,
    MemoryHierarchy,
    BusInterconnect,
    Unrecognised,
};

struct ErrorCode {
    std::uint16_t raw = 0;
    ErrorCodeKind kind = ErrorCodeKind::Unrecognised;
    std::string summary;             // "memory hierarchy error"
    std::string encoding;            // the matched form, e.g. "0000 0001 RRRR TTLL"
    std::vector<FieldRow> fields;    // TT / LL / RRRR / PP / II / T, as applicable
};

enum class Severity {
    Corrected,
    UncorrectedRecoverable,
    UncorrectedContextCorrupt,
};

// The plain-language layer spec §4.3 asks for: lead with the conclusion, then
// the evidence.
struct Verdict {
    Severity severity = Severity::Corrected;
    std::string headline;
    std::vector<std::string> notes;
};

struct StatusDecode {
    std::uint64_t raw = 0;
    Vendor vendor = Vendor::Unknown;

    StatusFlags flags;
    std::vector<BitRow> architectural_bits;   // [63:57]

    // MCA_STATUS[56:53]. AMD SMCA defines Deferred/Poison/TCC/SyndV in this
    // range; the exact assignment varies by family, so these are reported as
    // vendor-specific and flagged rather than asserted. Empty on Intel.
    std::vector<BitRow> vendor_bits;
    bool vendor_bits_are_provisional = false;

    // MCA_STATUS[31:16]. Intel calls this the model-specific error code; AMD
    // SMCA puts an ExtErrorCode in [21:16]. Reported raw either way.
    std::uint16_t model_specific = 0;

    ErrorCode error_code;
    Verdict verdict;

    // Anything the decoder could not resolve confidently (spec §6: a
    // confidently wrong diagnosis is worse than an admitted gap).
    std::vector<std::string> caveats;
};

[[nodiscard]] StatusDecode decode_status(std::uint64_t value, Vendor vendor);

// ---------------------------------------------------------------------------
// MCA_ADDR
// ---------------------------------------------------------------------------

enum class AddressClass {
    UserVirtual,       // low canonical
    KernelVirtual,     // high canonical
    PhysicalOrIndex,   // not a canonical VA
    NoAddress,         // all zero
};

struct AddressDecode {
    std::uint64_t raw = 0;
    Vendor vendor = Vendor::Unknown;

    // True when the SMCA split was applied, i.e. the value was *not* treated
    // as a flat address (spec §4.3).
    bool smca_layout = false;
    unsigned lsb_field = 0;             // [61:56] on SMCA: least significant valid bit
    std::uint64_t address_bits = 0;     // [55:0] on SMCA, the whole value otherwise
    std::uint64_t sign_extended = 0;    // address_bits sign-extended from bit 47

    AddressClass classification = AddressClass::PhysicalOrIndex;
    std::string classification_text;

    // How many low bits of the address are not significant, derived from the
    // LSB field. 0 means the full address is meaningful.
    unsigned insignificant_low_bits = 0;

    std::vector<std::string> caveats;
};

[[nodiscard]] AddressDecode decode_address(std::uint64_t value, Vendor vendor);

// ---------------------------------------------------------------------------
// MCA_MISC
// ---------------------------------------------------------------------------

struct MiscDecode {
    std::uint64_t raw = 0;
    Vendor vendor = Vendor::Unknown;

    // Intel SDM Vol. 3B: when MiscV is set, IA32_MCi_MISC[5:0] is the address
    // LSB and [8:6] the address mode. Everything above is model-specific.
    // AMD's MCA_MISC0 layout is family-specific, so nothing is claimed there.
    bool architectural_fields_apply = false;
    unsigned address_lsb = 0;
    unsigned address_mode = 0;
    std::string address_mode_text;

    std::uint64_t model_specific = 0;   // [63:9] on Intel, the whole value on AMD
    std::vector<std::string> caveats;
};

[[nodiscard]] MiscDecode decode_misc(std::uint64_t value, Vendor vendor, bool misc_valid);

// ---------------------------------------------------------------------------
// Shared text helpers, exposed so the renderer and the tests agree.
// ---------------------------------------------------------------------------

[[nodiscard]] std::string_view transaction_type_text(unsigned tt);   // TT
[[nodiscard]] std::string_view cache_level_text(unsigned ll);        // LL
[[nodiscard]] std::string_view request_text(unsigned rrrr);          // RRRR
[[nodiscard]] std::string_view participation_text(unsigned pp);      // PP
[[nodiscard]] std::string_view memory_io_text(unsigned ii);          // II
[[nodiscard]] std::string_view severity_text(Severity severity);
[[nodiscard]] std::string_view address_class_text(AddressClass value);

}  // namespace postmortem::mca
