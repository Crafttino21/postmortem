#include "check.hpp"
#include "core/cpu/signature.hpp"

using postmortem::cpu::decode_signature;
using postmortem::cpu::Signature;
using postmortem::cpu::Vendor;

PM_TEST(signature_decodes_the_spec_reference_part) {
    // Spec §7 pins the reference machine: Ryzen 9 5950X, family 19h, model
    // 21h, stepping 2. CPUID.1 EAX for Vermeer is 00A20F12h.
    const Signature sig = decode_signature(0x00A20F12u, Vendor::Amd);

    PM_CHECK_EQ(sig.family, 0x19u);
    PM_CHECK_EQ(sig.model, 0x21u);
    PM_CHECK_EQ(sig.stepping, 0x2u);

    // The encoded halves, which the output shows next to the result.
    PM_CHECK_EQ(sig.base_family, 0xFu);
    PM_CHECK_EQ(sig.extended_family, 0x0Au);
    PM_CHECK_EQ(sig.base_model, 0x1u);
    PM_CHECK_EQ(sig.extended_model, 0x2u);
    PM_CHECK_EQ(sig.raw, 0x00A20F12u);
}

PM_TEST(signature_decodes_intel_family_six) {
    // Haswell: 000306C3h -> family 6, model 3Ch, stepping 3.
    const Signature haswell = decode_signature(0x000306C3u, Vendor::Intel);
    PM_CHECK_EQ(haswell.family, 0x6u);
    PM_CHECK_EQ(haswell.model, 0x3Cu);
    PM_CHECK_EQ(haswell.stepping, 0x3u);

    // Alder Lake: 000906A4h -> family 6, model 9Ah, stepping 4.
    const Signature alder_lake = decode_signature(0x000906A4u, Vendor::Intel);
    PM_CHECK_EQ(alder_lake.family, 0x6u);
    PM_CHECK_EQ(alder_lake.model, 0x9Au);
    PM_CHECK_EQ(alder_lake.stepping, 0x4u);
}

PM_TEST(signature_extended_family_only_applies_at_base_family_0f) {
    // Pentium 4: base family 0Fh with a zero extended family stays 0Fh.
    const Signature p4 = decode_signature(0x00000F41u, Vendor::Intel);
    PM_CHECK_EQ(p4.family, 0xFu);
    PM_CHECK_EQ(p4.model, 0x4u);
    PM_CHECK_EQ(p4.stepping, 0x1u);
}

PM_TEST(signature_extended_model_rule_differs_between_vendors) {
    // Base family 06h with a non-zero extended model is the one encoding where
    // the two vendors' rules diverge: Intel folds the extended model in, AMD
    // does not. Getting this backwards silently misreports the model number.
    constexpr std::uint32_t kEax = 0x00160610u;

    const Signature as_intel = decode_signature(kEax, Vendor::Intel);
    PM_CHECK_EQ(as_intel.family, 0x6u);
    PM_CHECK_EQ(as_intel.model, 0x61u);

    const Signature as_amd = decode_signature(kEax, Vendor::Amd);
    PM_CHECK_EQ(as_amd.family, 0x6u);
    PM_CHECK_EQ(as_amd.model, 0x1u);
}

PM_TEST(signature_vendor_mapping) {
    PM_CHECK_EQ(postmortem::cpu::vendor_from_string("AuthenticAMD"), Vendor::Amd);
    PM_CHECK_EQ(postmortem::cpu::vendor_from_string("GenuineIntel"), Vendor::Intel);
    PM_CHECK_EQ(postmortem::cpu::vendor_from_string("Whatever"), Vendor::Unknown);
    PM_CHECK_EQ(postmortem::cpu::vendor_label(Vendor::Amd), std::string_view("AMD"));
    PM_CHECK(postmortem::cpu::vendor_label(Vendor::Unknown).empty());
}
