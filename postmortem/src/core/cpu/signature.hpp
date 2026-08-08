// CPUID leaf 1 EAX ("family/model/stepping") decoding.
//
// Pure arithmetic over a 32-bit register value, so it lives in the core
// library and is unit-tested against the §7 reference part (Ryzen 9 5950X,
// family 19h model 21h stepping 2) without needing that CPU present.
//
// Spec references:
//   Intel SDM Vol. 2A, CPUID - "Instruction Operation" for leaf 01H EAX,
//     including the DisplayFamily/DisplayModel pseudocode.
//   AMD APM Vol. 3, CPUID Fn0000_0001_EAX (Family, Model, Stepping ID).

#pragma once

#include <cstdint>
#include <string_view>

namespace postmortem::cpu {

enum class Vendor {
    Unknown,
    Intel,
    Amd,
};

struct Signature {
    std::uint32_t raw = 0;

    // Raw encoded fields, kept so output can show the bits next to the result
    // (spec §6: always show the raw value alongside the interpretation).
    unsigned base_family = 0;      // EAX[11:8]
    unsigned base_model = 0;       // EAX[7:4]
    unsigned extended_family = 0;  // EAX[27:20]
    unsigned extended_model = 0;   // EAX[19:16]

    // The values everyone actually quotes, e.g. "Family 19h, Model 21h".
    unsigned family = 0;
    unsigned model = 0;
    unsigned stepping = 0;         // EAX[3:0]
};

// Both vendors document the same encoding but different rules for when the
// extended fields participate, so the vendor must be known to decode
// correctly. Vendor::Unknown uses the Intel rule, which is the more
// permissive of the two.
[[nodiscard]] Signature decode_signature(std::uint32_t eax, Vendor vendor);

// Maps a CPUID leaf 0 vendor string ("AuthenticAMD", "GenuineIntel").
[[nodiscard]] Vendor vendor_from_string(std::string_view vendor_id);

// Short human label: "AMD", "Intel", or "" when unrecognised.
[[nodiscard]] std::string_view vendor_label(Vendor vendor);

}  // namespace postmortem::cpu
