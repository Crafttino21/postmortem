#include "platform/cpu_info.hpp"

#include <windows.h>

#include <intrin.h>

#include <array>
#include <bit>
#include <cstring>
#include <vector>

#include "platform/registry.hpp"
#include "platform/strings.hpp"

namespace postmortem::platform {
namespace {

constexpr const wchar_t* kCpuKey =
    L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";

struct CpuidRegisters {
    std::uint32_t eax = 0;
    std::uint32_t ebx = 0;
    std::uint32_t ecx = 0;
    std::uint32_t edx = 0;
};

CpuidRegisters cpuid(std::uint32_t leaf, std::uint32_t subleaf = 0) {
    std::array<int, 4> regs{};
    __cpuidex(regs.data(), static_cast<int>(leaf), static_cast<int>(subleaf));
    return CpuidRegisters{static_cast<std::uint32_t>(regs[0]), static_cast<std::uint32_t>(regs[1]),
                          static_cast<std::uint32_t>(regs[2]),
                          static_cast<std::uint32_t>(regs[3])};
}

// Appends a register's four bytes in little-endian order, as CPUID string
// leaves encode them.
void append_register(std::string& out, std::uint32_t reg) {
    for (int shift = 0; shift < 32; shift += 8) {
        const char c = static_cast<char>((reg >> shift) & 0xFF);
        if (c == '\0') return;
        out += c;
    }
}

std::string read_vendor_id() {
    const CpuidRegisters r = cpuid(0);
    std::string vendor;
    append_register(vendor, r.ebx);
    append_register(vendor, r.edx);
    append_register(vendor, r.ecx);
    return vendor;
}

// CPUID leaves 8000_0002..8000_0004 hold the 48-byte brand string. Absent on
// pre-2000 parts, hence the max-leaf check.
std::string read_brand_string() {
    if (cpuid(0x80000000u).eax < 0x80000004u) return {};

    std::string brand;
    for (std::uint32_t leaf = 0x80000002u; leaf <= 0x80000004u; ++leaf) {
        const CpuidRegisters r = cpuid(leaf);
        append_register(brand, r.eax);
        append_register(brand, r.ebx);
        append_register(brand, r.ecx);
        append_register(brand, r.edx);
    }
    return trim(brand);
}

// Leaf 4000_0000 is the hypervisor CPUID space (reserved for that purpose on
// both vendors). It only answers when the hypervisor-present bit is set.
std::string read_hypervisor_vendor() {
    const CpuidRegisters r = cpuid(0x40000000u);
    std::string vendor;
    append_register(vendor, r.ebx);
    append_register(vendor, r.ecx);
    append_register(vendor, r.edx);
    return trim(vendor);
}

void fill_topology(CpuInfo& info) {
    DWORD size = 0;
    if (::GetLogicalProcessorInformationEx(RelationAll, nullptr, &size) != FALSE ||
        ::GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return;
    }

    std::vector<std::byte> buffer(size);
    auto* first = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data());
    if (::GetLogicalProcessorInformationEx(RelationAll, first, &size) == FALSE) return;

    // Records are variable-length; walk them by their own Size field. The
    // fixed part being indexed here is Relationship + Size, so require that
    // much before dereferencing.
    constexpr DWORD kRecordHeaderSize =
        sizeof(LOGICAL_PROCESSOR_RELATIONSHIP) + sizeof(DWORD);
    for (DWORD offset = 0; offset + kRecordHeaderSize <= size;) {
        const auto* record =
            reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data() +
                                                                             offset);
        if (record->Size == 0 || offset + record->Size > size) break;

        switch (record->Relationship) {
            case RelationProcessorCore: {
                ++info.physical_cores;
                const WORD groups = record->Processor.GroupCount;
                for (WORD i = 0; i < groups; ++i) {
                    info.logical_processors += static_cast<unsigned>(
                        std::popcount(static_cast<std::uint64_t>(record->Processor.GroupMask[i].Mask)));
                }
                break;
            }
            case RelationNumaNode:
                ++info.numa_nodes;
                break;
            case RelationGroup:
                info.processor_groups = record->Group.ActiveGroupCount;
                break;
            default:
                break;
        }
        offset += record->Size;
    }

    info.topology_known = info.physical_cores > 0;
}

// Both vendors expose the revision through MSR 0x8B but in different halves:
// Intel returns it in EDX (IA32_BIOS_SIGN_ID, SDM Vol. 4), AMD in EAX
// (PATCH_LEVEL, APM Vol. 2). Where Windows stores the whole register pair the
// meaningful half follows the same split; where it stores a single DWORD (the
// AMD machines seen so far) there is nothing to disambiguate.
std::optional<MicrocodeRevision> parse_microcode(const std::vector<std::uint8_t>& bytes,
                                                 cpu::Vendor vendor) {
    MicrocodeRevision revision;

    if (bytes.size() >= sizeof(std::uint64_t)) {
        revision.raw_size_bytes = 8;
        std::memcpy(&revision.raw, bytes.data(), sizeof(revision.raw));

        switch (vendor) {
            case cpu::Vendor::Intel:
                revision.revision = static_cast<std::uint32_t>(revision.raw >> 32);
                revision.interpretation_certain = true;
                break;
            case cpu::Vendor::Amd:
                revision.revision = static_cast<std::uint32_t>(revision.raw & 0xFFFFFFFFull);
                revision.interpretation_certain = true;
                break;
            case cpu::Vendor::Unknown:
                // Report whichever half is non-zero, and admit the guess.
                revision.revision = (revision.raw & 0xFFFFFFFFull) != 0
                                        ? static_cast<std::uint32_t>(revision.raw & 0xFFFFFFFFull)
                                        : static_cast<std::uint32_t>(revision.raw >> 32);
                revision.interpretation_certain = false;
                break;
        }
        return revision;
    }

    if (bytes.size() >= sizeof(std::uint32_t)) {
        std::uint32_t value = 0;
        std::memcpy(&value, bytes.data(), sizeof(value));
        revision.raw_size_bytes = 4;
        revision.raw = value;
        revision.revision = value;
        revision.interpretation_certain = true;
        return revision;
    }

    return std::nullopt;
}

}  // namespace

CpuInfo query_cpu_info() {
    CpuInfo info;
    info.vendor_id = read_vendor_id();
    info.vendor = cpu::vendor_from_string(info.vendor_id);
    info.brand = read_brand_string();

    const CpuidRegisters leaf1 = cpuid(1);
    info.signature = cpu::decode_signature(leaf1.eax, info.vendor);

    // Leaf 1 ECX[31] is architecturally reserved-zero on bare metal and set by
    // every hypervisor that follows the convention.
    info.hypervisor_present = (leaf1.ecx & (1u << 31)) != 0;
    if (info.hypervisor_present) info.hypervisor_vendor = read_hypervisor_vendor();

    fill_topology(info);

    using registry::Hive;
    if (const auto bytes = registry::read_binary(Hive::LocalMachine, kCpuKey, L"Update Revision")) {
        info.microcode = parse_microcode(*bytes, info.vendor);
    }
    if (const auto bytes =
            registry::read_binary(Hive::LocalMachine, kCpuKey, L"Previous Update Revision")) {
        info.microcode_previous = parse_microcode(*bytes, info.vendor);
    }
    if (const auto mhz = registry::read_dword(Hive::LocalMachine, kCpuKey, L"~MHz")) {
        info.nominal_mhz = *mhz;
    }

    // The brand string is the friendlier name, but fall back to the registry
    // copy if CPUID did not provide one.
    if (info.brand.empty()) {
        if (const auto name =
                registry::read_string(Hive::LocalMachine, kCpuKey, L"ProcessorNameString")) {
            info.brand = *name;
        }
    }

    return info;
}

}  // namespace postmortem::platform
