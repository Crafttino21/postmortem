// The §7 reference vectors: seven real WHEA records from a Ryzen 9 5950X
// (family 19h, model 21h, stepping 2), all bank 5.
//
// These are the values that made the tool necessary, so they are the values it
// has to decode correctly. Every expectation the spec states explicitly is
// asserted here verbatim.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "check.hpp"
#include "core/mca/registers.hpp"

using postmortem::cpu::Vendor;
using postmortem::mca::AddressClass;
using postmortem::mca::ErrorCodeKind;
using postmortem::mca::Severity;

namespace {

struct Vector {
    std::uint64_t status;
    std::uint64_t address;
    unsigned apic_id;
};

// Spec §7, verbatim.
const std::vector<Vector>& reference_vectors() {
    static const std::vector<Vector> vectors{
        {0xbea0000000000108ull, 0x1fff800b3409a9aull, 5},
        {0xbea0000000000108ull, 0x7fffc45c42feull, 11},
        {0xbea0000001000108ull, 0x7ff913a99f3bull, 17},
        {0xbea0000001000108ull, 0x7ff9a369eec3ull, 11},
        {0xbea0000001000108ull, 0x1fff85925d93b31ull, 7},
        {0xbea0000000000108ull, 0x7ffd4a38145eull, 10},
        {0xbea0000001000108ull, 0x1fff800c062b2a9ull, 11},
    };
    return vectors;
}

constexpr std::uint64_t kReferenceMisc = 0xd0130fff00000000ull;

const postmortem::mca::FieldRow* find_field(const postmortem::mca::ErrorCode& code,
                                            std::string_view prefix) {
    for (const auto& row : code.fields) {
        if (row.name.rfind(prefix.data(), 0, prefix.size()) == 0) return &row;
    }
    return nullptr;
}

}  // namespace

PM_TEST(mca_status_architectural_bits_match_the_spec_expectation) {
    // Spec §7: "Expected decode for 0xbea0000000000108: Val=1, Overflow=0,
    // UC=1, Enabled=1, MiscV=1, AddrV=1, PCC=1".
    const auto decode = postmortem::mca::decode_status(0xbea0000000000108ull, Vendor::Amd);

    PM_CHECK(decode.flags.valid);
    PM_CHECK(!decode.flags.overflow);
    PM_CHECK(decode.flags.uncorrected);
    PM_CHECK(decode.flags.enabled);
    PM_CHECK(decode.flags.misc_valid);
    PM_CHECK(decode.flags.address_valid);
    PM_CHECK(decode.flags.context_corrupt);

    // The bit table that gets rendered must carry the same seven bits.
    PM_CHECK_EQ(decode.architectural_bits.size(), std::size_t{7});
    PM_CHECK_EQ(decode.architectural_bits.front().position, 63);
    PM_CHECK_EQ(decode.architectural_bits.back().position, 57);
}

PM_TEST(mca_status_error_code_is_a_memory_hierarchy_error) {
    // Spec §7: "error code 0x0108 = memory-hierarchy error, TT=Generic,
    // LL=L0/L1".
    const auto decode = postmortem::mca::decode_status(0xbea0000000000108ull, Vendor::Amd);
    const auto& code = decode.error_code;

    PM_CHECK_EQ(code.raw, std::uint16_t{0x0108});
    PM_CHECK_EQ(code.kind, ErrorCodeKind::MemoryHierarchy);
    PM_CHECK_EQ(code.encoding, std::string("0000 0001 RRRR TTLL"));

    const auto* tt = find_field(code, "Transaction type");
    PM_CHECK(tt != nullptr);
    if (tt != nullptr) {
        PM_CHECK_EQ(tt->value, std::uint64_t{0b10});
        PM_CHECK_EQ(tt->meaning, std::string("Generic"));
    }

    const auto* ll = find_field(code, "Cache level");
    PM_CHECK(ll != nullptr);
    if (ll != nullptr) {
        // LL=00 is level 0 in the encoding, which is the L1 cache in product
        // terms - the spec writes this as "L0/L1".
        PM_CHECK_EQ(ll->value, std::uint64_t{0b00});
        PM_CHECK(ll->meaning.find("L0") != std::string::npos);
        PM_CHECK(ll->meaning.find("L1") != std::string::npos);
    }

    const auto* request = find_field(code, "Request");
    PM_CHECK(request != nullptr);
    if (request != nullptr) PM_CHECK_EQ(request->value, std::uint64_t{0b0000});
}

PM_TEST(mca_status_verdict_explains_the_missing_crash_dump) {
    // This is the whole reason the tool exists: UC=1 with PCC=1 means the CPU
    // reset before Windows could write anything.
    const auto decode = postmortem::mca::decode_status(0xbea0000000000108ull, Vendor::Amd);

    PM_CHECK_EQ(decode.verdict.severity, Severity::UncorrectedContextCorrupt);
    PM_CHECK(decode.verdict.headline.find("no crash dump") != std::string::npos);
    PM_CHECK(decode.verdict.headline.find("no bugcheck") != std::string::npos);
}

PM_TEST(mca_status_verdict_covers_the_other_three_cases) {
    // UC=1, PCC=0 -> bugcheck 0x124 is expected. Bits [59:56] are 0xC, i.e.
    // MiscV=1 AddrV=1 PCC=0.
    const auto recoverable = postmortem::mca::decode_status(0xbca0000000000108ull, Vendor::Amd);
    PM_CHECK(recoverable.flags.uncorrected);
    PM_CHECK(!recoverable.flags.context_corrupt);
    PM_CHECK_EQ(recoverable.verdict.severity, Severity::UncorrectedRecoverable);
    PM_CHECK(recoverable.verdict.headline.find("0x124") != std::string::npos);

    // UC=0 -> corrected. Bits [63:60] are 0x9, i.e. Val=1 Overflow=0 UC=0 En=1.
    const auto corrected = postmortem::mca::decode_status(0x9ca0000000000108ull, Vendor::Amd);
    PM_CHECK(!corrected.flags.uncorrected);
    PM_CHECK_EQ(corrected.verdict.severity, Severity::Corrected);
    PM_CHECK(corrected.verdict.headline.find("corrected") != std::string::npos);

    // Overflow=1 -> earlier errors were lost.
    const auto overflowed = postmortem::mca::decode_status(0xfea0000000000108ull, Vendor::Amd);
    PM_CHECK(overflowed.flags.overflow);
    bool mentions_loss = false;
    for (const std::string& note : overflowed.verdict.notes) {
        if (note.find("lost") != std::string::npos) mentions_loss = true;
    }
    PM_CHECK(mentions_loss);

    // Val=0 -> the record is not evidence at all.
    const auto invalid = postmortem::mca::decode_status(0x3ea0000000000108ull, Vendor::Amd);
    PM_CHECK(!invalid.flags.valid);
    PM_CHECK(invalid.verdict.headline.find("no valid error record") != std::string::npos);
}

PM_TEST(mca_status_reports_the_model_specific_half_without_interpreting_it) {
    // Four of the seven vectors differ from the other three only in
    // MCA_STATUS[31:16]; the architectural meaning is identical.
    const auto plain = postmortem::mca::decode_status(0xbea0000000000108ull, Vendor::Amd);
    const auto flagged = postmortem::mca::decode_status(0xbea0000001000108ull, Vendor::Amd);

    PM_CHECK_EQ(plain.model_specific, std::uint16_t{0x0000});
    PM_CHECK_EQ(flagged.model_specific, std::uint16_t{0x0100});
    PM_CHECK_EQ(flagged.error_code.raw, plain.error_code.raw);
    PM_CHECK_EQ(flagged.verdict.severity, plain.verdict.severity);

    // It must be surfaced as an admitted gap rather than silently dropped.
    bool mentions_model_specific = false;
    for (const std::string& caveat : flagged.caveats) {
        if (caveat.find("model-specific") != std::string::npos) mentions_model_specific = true;
    }
    PM_CHECK(mentions_model_specific);
}

PM_TEST(mca_status_smca_bits_are_flagged_as_provisional) {
    const auto amd = postmortem::mca::decode_status(0xbea0000000000108ull, Vendor::Amd);
    PM_CHECK(amd.vendor_bits_are_provisional);
    PM_CHECK_EQ(amd.vendor_bits.size(), std::size_t{4});
    // 0xA in bits [56:53]: 1010 -> [56]=0 [55]=1 [54]=0 [53]=1.
    PM_CHECK(!amd.vendor_bits[0].value);
    PM_CHECK(amd.vendor_bits[1].value);
    PM_CHECK(!amd.vendor_bits[2].value);
    PM_CHECK(amd.vendor_bits[3].value);

    // Intel has no SMCA bits there, so none are claimed.
    const auto intel = postmortem::mca::decode_status(0xbea0000000000108ull, Vendor::Intel);
    PM_CHECK(intel.vendor_bits.empty());
    PM_CHECK(!intel.vendor_bits_are_provisional);
}

PM_TEST(mca_address_kernel_vector_matches_the_spec_expectation) {
    // Spec §7: "Expected decode for MciAddr 0x1fff800c062b2a9: LSB field = 1,
    // address bits [55:0] = 0xFFF800C062B2A9, sign-extended =
    // 0xFFFFF800C062B2A9, classification = kernel-mode virtual address."
    const auto decode = postmortem::mca::decode_address(0x1fff800c062b2a9ull, Vendor::Amd);

    PM_CHECK_EQ(decode.lsb_field, 1u);
    PM_CHECK_EQ(decode.address_bits, 0xFFF800C062B2A9ull);
    PM_CHECK_EQ(decode.sign_extended, 0xFFFFF800C062B2A9ull);
    PM_CHECK_EQ(decode.classification, AddressClass::KernelVirtual);
    PM_CHECK(decode.smca_layout);
}

PM_TEST(mca_address_user_vector_matches_the_spec_expectation) {
    // Spec §7: "Expected decode for MciAddr 0x7ffd4a38145e: LSB field = 0,
    // classification = user-mode virtual address."
    const auto decode = postmortem::mca::decode_address(0x7ffd4a38145eull, Vendor::Amd);

    PM_CHECK_EQ(decode.lsb_field, 0u);
    PM_CHECK_EQ(decode.address_bits, 0x7FFD4A38145Eull);
    PM_CHECK_EQ(decode.sign_extended, 0x00007FFD4A38145Eull);
    PM_CHECK_EQ(decode.classification, AddressClass::UserVirtual);
}

PM_TEST(mca_address_classifies_every_reference_vector) {
    // The four low addresses are user-mode, the three with an LSB field of 1
    // are kernel-mode. Getting this split right is what tells the user whether
    // the fault landed in their own code or in the kernel.
    const std::vector<AddressClass> expected{
        AddressClass::KernelVirtual,  // 0x1fff800b3409a9a
        AddressClass::UserVirtual,    // 0x7fffc45c42fe
        AddressClass::UserVirtual,    // 0x7ff913a99f3b
        AddressClass::UserVirtual,    // 0x7ff9a369eec3
        AddressClass::KernelVirtual,  // 0x1fff85925d93b31
        AddressClass::UserVirtual,    // 0x7ffd4a38145e
        AddressClass::KernelVirtual,  // 0x1fff800c062b2a9
    };

    const auto& vectors = reference_vectors();
    PM_CHECK_EQ(vectors.size(), expected.size());

    for (std::size_t i = 0; i < vectors.size() && i < expected.size(); ++i) {
        const auto decode = postmortem::mca::decode_address(vectors[i].address, Vendor::Amd);
        PM_CHECK_EQ(decode.classification, expected[i]);

        // Every kernel-mode result must sign-extend into the high half.
        if (expected[i] == AddressClass::KernelVirtual) {
            PM_CHECK_EQ(decode.lsb_field, 1u);
            PM_CHECK(decode.sign_extended >= 0xFFFF800000000000ull);
        } else {
            PM_CHECK_EQ(decode.lsb_field, 0u);
            PM_CHECK(decode.sign_extended <= 0x00007FFFFFFFFFFFull);
        }
    }
}

PM_TEST(mca_address_every_reference_status_decodes_identically) {
    // All seven records are the same architectural error; only the
    // model-specific half and the address differ. A regression that changed
    // the verdict for some of them would be easy to miss.
    for (const Vector& vector : reference_vectors()) {
        const auto decode = postmortem::mca::decode_status(vector.status, Vendor::Amd);
        PM_CHECK_EQ(decode.error_code.raw, std::uint16_t{0x0108});
        PM_CHECK_EQ(decode.error_code.kind, ErrorCodeKind::MemoryHierarchy);
        PM_CHECK_EQ(decode.verdict.severity, Severity::UncorrectedContextCorrupt);
        PM_CHECK(decode.flags.address_valid);
    }
}

PM_TEST(mca_address_intel_treats_the_register_as_flat) {
    // On Intel there is no LSB field: bits [61:56] are part of the address.
    const auto decode = postmortem::mca::decode_address(0x1fff800c062b2a9ull, Vendor::Intel);
    PM_CHECK(!decode.smca_layout);
    PM_CHECK_EQ(decode.lsb_field, 0u);
    PM_CHECK_EQ(decode.address_bits, 0x1fff800c062b2a9ull);
    // Bits above 47 do not match the sign bit, so this is not a canonical
    // virtual address at all.
    PM_CHECK_EQ(decode.classification, AddressClass::PhysicalOrIndex);
}

PM_TEST(mca_address_identifies_a_non_canonical_value) {
    // A physical address with bits set above 47 that do not agree with bit 47
    // cannot be a virtual address, and must not be reported as one.
    const auto decode = postmortem::mca::decode_address(0x0012345678901234ull, Vendor::Amd);
    PM_CHECK_EQ(decode.classification, AddressClass::PhysicalOrIndex);

    const auto zero = postmortem::mca::decode_address(0, Vendor::Amd);
    PM_CHECK_EQ(zero.classification, AddressClass::NoAddress);
}

PM_TEST(mca_address_lsb_field_reports_the_fault_granularity) {
    // LSB field 6 means the low 6 bits are not significant: a 64-byte region,
    // i.e. one cache line.
    const std::uint64_t value = (6ull << 56) | 0x7FFD4A38145Eull;
    const auto decode = postmortem::mca::decode_address(value, Vendor::Amd);

    PM_CHECK_EQ(decode.lsb_field, 6u);
    PM_CHECK_EQ(decode.insignificant_low_bits, 6u);
    bool mentions_region = false;
    for (const std::string& caveat : decode.caveats) {
        if (caveat.find("64-byte region") != std::string::npos) mentions_region = true;
    }
    PM_CHECK(mentions_region);
}

PM_TEST(mca_misc_is_reported_raw_on_amd) {
    const auto decode = postmortem::mca::decode_misc(kReferenceMisc, Vendor::Amd, true);
    PM_CHECK(!decode.architectural_fields_apply);
    PM_CHECK_EQ(decode.model_specific, kReferenceMisc);
    PM_CHECK(!decode.caveats.empty());
}

PM_TEST(mca_misc_decodes_the_architectural_fields_on_intel) {
    // Address LSB 0x0C in [5:0], address mode 2 (physical) in [8:6].
    const std::uint64_t value = (2ull << 6) | 0x0Cull;
    const auto decode = postmortem::mca::decode_misc(value, Vendor::Intel, true);

    PM_CHECK(decode.architectural_fields_apply);
    PM_CHECK_EQ(decode.address_lsb, 0x0Cu);
    PM_CHECK_EQ(decode.address_mode, 2u);
    PM_CHECK_EQ(decode.address_mode_text, std::string("physical address"));
}

PM_TEST(mca_misc_says_nothing_when_miscv_is_clear) {
    const auto decode = postmortem::mca::decode_misc(kReferenceMisc, Vendor::Intel, false);
    PM_CHECK(!decode.architectural_fields_apply);
    PM_CHECK(!decode.caveats.empty());
}

PM_TEST(mca_error_code_decodes_the_other_compound_forms) {
    using postmortem::mca::decode_status;

    // TLB error, 0000 0000 0001 TTLL: TT=01 (data), LL=10 (L2).
    const auto tlb = decode_status(0xbe00000000000016ull, Vendor::Amd);
    PM_CHECK_EQ(tlb.error_code.kind, ErrorCodeKind::TlbError);
    PM_CHECK_EQ(tlb.error_code.fields.size(), std::size_t{2});

    // Bus/interconnect, 0000 1PPT RRRR IILL: 0x0E0F.
    const auto bus = decode_status(0xbe00000000000e0full, Vendor::Amd);
    PM_CHECK_EQ(bus.error_code.kind, ErrorCodeKind::BusInterconnect);
    PM_CHECK_EQ(bus.error_code.fields.size(), std::size_t{5});

    // Generic cache hierarchy, 0000 0000 0000 11LL.
    const auto cache = decode_status(0xbe0000000000000full, Vendor::Amd);
    PM_CHECK_EQ(cache.error_code.kind, ErrorCodeKind::GenericCacheHierarchy);

    // Simple codes.
    PM_CHECK_EQ(decode_status(0xbe00000000000000ull, Vendor::Amd).error_code.kind,
                ErrorCodeKind::NoError);
    PM_CHECK_EQ(decode_status(0xbe00000000000001ull, Vendor::Amd).error_code.kind,
                ErrorCodeKind::Unclassified);
    PM_CHECK_EQ(decode_status(0xbe00000000000400ull, Vendor::Amd).error_code.kind,
                ErrorCodeKind::InternalTimer);
    PM_CHECK_EQ(decode_status(0xbe00000000000403ull, Vendor::Amd).error_code.kind,
                ErrorCodeKind::InternalWatchdog);

    // An encoding no form matches must be admitted, not guessed at.
    const auto unknown = decode_status(0xbe00000000007777ull, Vendor::Amd);
    PM_CHECK_EQ(unknown.error_code.kind, ErrorCodeKind::Unrecognised);
    PM_CHECK_EQ(unknown.error_code.raw, std::uint16_t{0x7777});
}
