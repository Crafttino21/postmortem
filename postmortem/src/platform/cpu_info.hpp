#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "core/cpu/signature.hpp"

namespace postmortem::platform {

// Microcode revision as recorded by the loader at boot.
//
// There is no user-mode way to read MSR 0x8B (IA32_BIOS_SIGN_ID /
// AMD PATCH_LEVEL) and spec §2 forbids the kernel driver that would allow it,
// so this comes from HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0.
//
// The blob's width varies: 8 bytes (the full EDX:EAX pair) on Intel, 4 bytes
// on the AMD machines checked so far. With 8 bytes the meaningful half depends
// on the vendor, so the raw value travels alongside the interpretation.
struct MicrocodeRevision {
    std::uint64_t raw = 0;             // the registry bytes, little-endian
    unsigned raw_size_bytes = 0;       // 4 or 8
    std::uint32_t revision = 0;        // the interpreted half
    bool interpretation_certain = false;
};

struct CpuInfo {
    std::string vendor_id;             // CPUID leaf 0, e.g. "AuthenticAMD"
    cpu::Vendor vendor = cpu::Vendor::Unknown;
    std::string brand;                 // CPUID leaves 8000_0002..8000_0004
    cpu::Signature signature;

    // Topology counts from GetLogicalProcessorInformationEx. The full APIC ->
    // core/CCD mapping is milestone 5; this is only the headline count.
    bool topology_known = false;
    unsigned physical_cores = 0;
    unsigned logical_processors = 0;
    unsigned numa_nodes = 0;
    unsigned processor_groups = 0;

    // CPUID leaf 1 ECX[31] plus the leaf 4000_0000 vendor string. Relevant to
    // crash forensics because a hypervisor changes how WHEA errors surface.
    bool hypervisor_present = false;
    std::string hypervisor_vendor;

    std::optional<MicrocodeRevision> microcode;
    std::optional<MicrocodeRevision> microcode_previous;
    std::optional<unsigned> nominal_mhz;
};

[[nodiscard]] CpuInfo query_cpu_info();

}  // namespace postmortem::platform
