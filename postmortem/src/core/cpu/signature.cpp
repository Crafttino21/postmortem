#include "core/cpu/signature.hpp"

namespace postmortem::cpu {

Signature decode_signature(std::uint32_t eax, Vendor vendor) {
    Signature sig;
    sig.raw = eax;
    sig.stepping = eax & 0xFu;
    sig.base_model = (eax >> 4) & 0xFu;
    sig.base_family = (eax >> 8) & 0xFu;
    sig.extended_model = (eax >> 16) & 0xFu;
    sig.extended_family = (eax >> 20) & 0xFFu;

    // Family: identical rule on both vendors - the extended field is added
    // only when the base family is 0Fh.
    sig.family = sig.base_family;
    if (sig.base_family == 0xFu) sig.family += sig.extended_family;

    // Model: Intel folds the extended model in when the base family is 06h or
    // 0Fh (SDM Vol. 2A, leaf 01H); AMD does so only when the base family is
    // 0Fh (APM Vol. 3, Fn0000_0001_EAX). The distinction only matters for base
    // family 06h parts, where AMD has not shipped since the K7.
    const bool use_extended_model =
        vendor == Vendor::Amd
            ? sig.base_family == 0xFu
            : (sig.base_family == 0x6u || sig.base_family == 0xFu);

    sig.model = use_extended_model ? ((sig.extended_model << 4) | sig.base_model)
                                   : sig.base_model;
    return sig;
}

Vendor vendor_from_string(std::string_view vendor_id) {
    if (vendor_id == "AuthenticAMD") return Vendor::Amd;
    if (vendor_id == "GenuineIntel") return Vendor::Intel;
    return Vendor::Unknown;
}

std::string_view vendor_label(Vendor vendor) {
    switch (vendor) {
        case Vendor::Amd:   return "AMD";
        case Vendor::Intel: return "Intel";
        case Vendor::Unknown: break;
    }
    return {};
}

}  // namespace postmortem::cpu
