#include "platform/cpu_topology.hpp"

#include <windows.h>

#include <intrin.h>

#include <algorithm>
#include <array>
#include <bit>
#include <map>

#include "core/cpu/signature.hpp"
#include "platform/cpu_info.hpp"

namespace postmortem::platform {
namespace {

struct Regs {
    std::uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
};

Regs cpuid(std::uint32_t leaf, std::uint32_t subleaf = 0) {
    std::array<int, 4> regs{};
    __cpuidex(regs.data(), static_cast<int>(leaf), static_cast<int>(subleaf));
    return Regs{static_cast<std::uint32_t>(regs[0]), static_cast<std::uint32_t>(regs[1]),
                static_cast<std::uint32_t>(regs[2]), static_cast<std::uint32_t>(regs[3])};
}

std::uint32_t max_leaf() {
    return cpuid(0).eax;
}

std::uint32_t max_extended_leaf() {
    return cpuid(0x80000000u).eax;
}

// Reads the APIC ID of the *current* processor. Prefers the 32-bit x2APIC ID
// from leaf 1Fh/0Bh; falls back to leaf 1 EBX[31:24], which is only 8 bits and
// therefore ambiguous above 256 logical processors.
std::uint32_t read_apic_id(bool& is_x2) {
    const std::uint32_t leaves = max_leaf();

    if (leaves >= 0x1F) {
        const Regs r = cpuid(0x1F, 0);
        if (r.ebx != 0) {
            is_x2 = true;
            return r.edx;
        }
    }
    if (leaves >= 0x0B) {
        const Regs r = cpuid(0x0B, 0);
        if (r.ebx != 0) {
            is_x2 = true;
            return r.edx;
        }
    }
    is_x2 = false;
    return (cpuid(1).ebx >> 24) & 0xFFu;
}

// Shift widths from the extended topology enumeration: how many low bits of
// the APIC ID identify the SMT thread and the core.
struct TopologyShifts {
    bool valid = false;
    unsigned smt_shift = 0;
    unsigned core_shift = 0;
};

TopologyShifts read_shifts() {
    TopologyShifts shifts;
    const std::uint32_t leaves = max_leaf();
    const std::uint32_t leaf = leaves >= 0x1F ? 0x1Fu : (leaves >= 0x0B ? 0x0Bu : 0u);
    if (leaf == 0) return shifts;

    // Level types: 1 = SMT, 2 = Core. Higher levels (module, tile, die) are
    // above the core and do not affect the two shifts we need.
    for (std::uint32_t subleaf = 0; subleaf < 8; ++subleaf) {
        const Regs r = cpuid(leaf, subleaf);
        const unsigned level_type = (r.ecx >> 8) & 0xFFu;
        const unsigned shift = r.eax & 0x1Fu;
        if (level_type == 0) break;
        if (level_type == 1) {
            shifts.smt_shift = shift;
            shifts.valid = true;
        } else if (level_type == 2) {
            shifts.core_shift = shift;
            shifts.valid = true;
        }
    }
    return shifts;
}

// AMD leaf 8000_001Eh: EBX[7:0] is the compute-unit/core ID, EBX[15:8] the
// threads-per-core minus one, ECX[7:0] the node ID (APM Vol. 3).
struct AmdExtendedIds {
    bool valid = false;
    unsigned core_id = 0;
    unsigned threads_per_core = 1;
    unsigned node_id = 0;
};

AmdExtendedIds read_amd_extended_ids() {
    AmdExtendedIds ids;
    if (max_extended_leaf() < 0x8000001Eu) return ids;

    const Regs r = cpuid(0x8000001Eu);
    ids.valid = true;
    ids.core_id = r.ebx & 0xFFu;
    ids.threads_per_core = ((r.ebx >> 8) & 0xFFu) + 1;
    ids.node_id = r.ecx & 0xFFu;
    return ids;
}

// Intel leaf 1Ah: EAX[31:24] is the core type. 0x40 = E-core (Atom),
// 0x20 = P-core (Core). Absent on non-hybrid parts.
std::optional<bool> read_intel_core_type() {
    if (max_leaf() < 0x1A) return std::nullopt;
    const Regs r = cpuid(0x1A);
    const unsigned type = (r.eax >> 24) & 0xFFu;
    if (type == 0) return std::nullopt;
    return type == 0x40u ? std::optional<bool>(false) : std::optional<bool>(true);
}

struct GroupAffinityTarget {
    WORD group = 0;
    KAFFINITY mask = 0;
    unsigned index_in_group = 0;
};

// Enumerates every logical processor as a group + single-bit mask, which is
// what SetThreadGroupAffinity needs.
std::vector<GroupAffinityTarget> enumerate_processors(std::string& error) {
    std::vector<GroupAffinityTarget> targets;

    DWORD size = 0;
    if (::GetLogicalProcessorInformationEx(RelationGroup, nullptr, &size) != FALSE ||
        ::GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        error = "GetLogicalProcessorInformationEx(RelationGroup) failed";
        return targets;
    }

    std::vector<std::byte> buffer(size);
    auto* info = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data());
    if (::GetLogicalProcessorInformationEx(RelationGroup, info, &size) == FALSE) {
        error = "GetLogicalProcessorInformationEx(RelationGroup) failed on the second call";
        return targets;
    }

    for (DWORD offset = 0; offset + sizeof(DWORD) * 2 <= size;) {
        const auto* record =
            reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data() +
                                                                             offset);
        if (record->Size == 0 || offset + record->Size > size) break;
        if (record->Relationship == RelationGroup) {
            const WORD groups = record->Group.ActiveGroupCount;
            for (WORD g = 0; g < groups; ++g) {
                const KAFFINITY mask = record->Group.GroupInfo[g].ActiveProcessorMask;
                for (unsigned bit = 0; bit < sizeof(KAFFINITY) * 8; ++bit) {
                    const KAFFINITY single = static_cast<KAFFINITY>(1) << bit;
                    if ((mask & single) == 0) continue;
                    targets.push_back(GroupAffinityTarget{g, single, bit});
                }
            }
        }
        offset += record->Size;
    }
    return targets;
}

// Groups logical processors by which set shares an L3 cache. On AMD that set
// is the CCX; on Intel hybrid parts it is the cluster.
std::map<std::uint64_t, unsigned> build_l3_groups(unsigned& complex_count) {
    std::map<std::uint64_t, unsigned> assignment;   // (group<<32 | index) -> complex
    complex_count = 0;

    DWORD size = 0;
    if (::GetLogicalProcessorInformationEx(RelationCache, nullptr, &size) != FALSE ||
        ::GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return assignment;
    }

    std::vector<std::byte> buffer(size);
    auto* info = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data());
    if (::GetLogicalProcessorInformationEx(RelationCache, info, &size) == FALSE) {
        return assignment;
    }

    for (DWORD offset = 0; offset + sizeof(DWORD) * 2 <= size;) {
        const auto* record =
            reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data() +
                                                                             offset);
        if (record->Size == 0 || offset + record->Size > size) break;

        if (record->Relationship == RelationCache && record->Cache.Level == 3) {
            const unsigned complex = complex_count++;
            const WORD group_count = record->Cache.GroupCount;
            // GroupCount is only meaningful from Windows 10 1809 onward; when
            // it is zero the single GroupMask member applies.
            if (group_count == 0) {
                const GROUP_AFFINITY& affinity = record->Cache.GroupMask;
                for (unsigned bit = 0; bit < sizeof(KAFFINITY) * 8; ++bit) {
                    if ((affinity.Mask & (static_cast<KAFFINITY>(1) << bit)) == 0) continue;
                    assignment[(static_cast<std::uint64_t>(affinity.Group) << 32) | bit] = complex;
                }
            } else {
                for (WORD g = 0; g < group_count; ++g) {
                    const GROUP_AFFINITY& affinity = record->Cache.GroupMasks[g];
                    for (unsigned bit = 0; bit < sizeof(KAFFINITY) * 8; ++bit) {
                        if ((affinity.Mask & (static_cast<KAFFINITY>(1) << bit)) == 0) continue;
                        assignment[(static_cast<std::uint64_t>(affinity.Group) << 32) | bit] =
                            complex;
                    }
                }
            }
        }
        offset += record->Size;
    }
    return assignment;
}

}  // namespace

std::string LogicalProcessor::describe() const {
    std::string out = "CPU " + std::to_string(os_index);
    if (core_id.has_value()) {
        out += " (core " + std::to_string(*core_id);
        if (thread_id.has_value()) out += ", thread " + std::to_string(*thread_id);
        if (l3_complex.has_value()) out += ", L3 complex " + std::to_string(*l3_complex);
        if (is_performance_core.has_value()) {
            out += *is_performance_core ? ", P-core" : ", E-core";
        }
        out += ")";
    }
    return out;
}

const LogicalProcessor* TopologyMap::find_by_apic_id(std::uint32_t apic_id) const {
    for (const LogicalProcessor& processor : processors) {
        if (processor.apic_id == apic_id) return &processor;
    }
    return nullptr;
}

TopologyMap query_topology() {
    TopologyMap map;

    const CpuInfo cpu = query_cpu_info();
    map.vendor = std::string(cpu::vendor_label(cpu.vendor));

    std::string error;
    const std::vector<GroupAffinityTarget> targets = enumerate_processors(error);
    if (targets.empty()) {
        map.error = error.empty() ? "no logical processors were enumerated" : error;
        return map;
    }

    unsigned complex_count = 0;
    const std::map<std::uint64_t, unsigned> l3_groups = build_l3_groups(complex_count);

    const TopologyShifts shifts = read_shifts();
    if (!shifts.valid) {
        map.caveats.emplace_back(
            "CPUID leaf 1Fh/0Bh did not report the extended topology enumeration, so core and "
            "thread numbers are derived from Windows' processor numbering instead of the APIC "
            "ID layout");
    }

    // Affinitise to each processor in turn. The original affinity is restored
    // before returning, so a caller's own placement is unaffected.
    const HANDLE thread = ::GetCurrentThread();
    GROUP_AFFINITY previous{};
    const bool saved = ::GetThreadGroupAffinity(thread, &previous) != FALSE;

    for (unsigned index = 0; index < targets.size(); ++index) {
        const GroupAffinityTarget& target = targets[index];

        GROUP_AFFINITY affinity{};
        affinity.Group = target.group;
        affinity.Mask = target.mask;
        if (::SetThreadGroupAffinity(thread, &affinity, nullptr) == FALSE) {
            map.caveats.push_back("could not move onto CPU " + std::to_string(index) +
                                  ", so its APIC ID is unknown");
            continue;
        }

        LogicalProcessor processor;
        processor.group = target.group;
        processor.index_in_group = target.index_in_group;
        processor.os_index = index;
        processor.apic_id = read_apic_id(processor.apic_id_is_x2);

        if (shifts.valid) {
            processor.thread_id = processor.apic_id & ((1u << shifts.smt_shift) - 1);
            processor.core_id = (processor.apic_id >> shifts.smt_shift) &
                                ((1u << (shifts.core_shift - shifts.smt_shift)) - 1);
            processor.package_id = processor.apic_id >> shifts.core_shift;
        }

        if (cpu.vendor == cpu::Vendor::Amd) {
            if (const AmdExtendedIds ids = read_amd_extended_ids(); ids.valid) {
                processor.core_id = ids.core_id;
                if (ids.threads_per_core > 1 && shifts.valid) {
                    processor.thread_id = processor.apic_id & ((1u << shifts.smt_shift) - 1);
                }
                processor.package_id = ids.node_id;
            }
        } else if (cpu.vendor == cpu::Vendor::Intel) {
            processor.is_performance_core = read_intel_core_type();
            if (processor.is_performance_core.has_value()) map.hybrid = true;
        }

        const auto key = (static_cast<std::uint64_t>(target.group) << 32) | target.index_in_group;
        if (const auto found = l3_groups.find(key); found != l3_groups.end()) {
            processor.l3_complex = found->second;
        }

        map.processors.push_back(processor);
    }

    if (saved) ::SetThreadGroupAffinity(thread, &previous, nullptr);

    map.l3_complexes = complex_count;
    map.physical_cores = cpu.physical_cores;

    // Duplicate APIC IDs mean the 8-bit fallback wrapped; say so rather than
    // silently mapping two cores to one ID.
    std::vector<std::uint32_t> ids;
    ids.reserve(map.processors.size());
    for (const LogicalProcessor& processor : map.processors) ids.push_back(processor.apic_id);
    std::sort(ids.begin(), ids.end());
    if (std::adjacent_find(ids.begin(), ids.end()) != ids.end()) {
        map.caveats.emplace_back(
            "two logical processors reported the same APIC ID, so the mapping is ambiguous - "
            "this happens when only the 8-bit legacy APIC ID is available");
    }
    if (!map.processors.empty() && !map.processors.front().apic_id_is_x2) {
        map.caveats.emplace_back(
            "only the 8-bit legacy APIC ID was available; on a machine with more than 256 "
            "logical processors it cannot identify a core uniquely");
    }

    map.available = !map.processors.empty();
    if (!map.available) map.error = "no processor could be queried";
    return map;
}

}  // namespace postmortem::platform
