// APIC ID to physical structure mapping (spec §4.4).
//
// "APIC IDs are meaningless to a user. Map them to physical structure."
//
// CPUID reports the APIC ID of whichever logical processor executes it, so the
// only way to enumerate them is to affinitise the thread to each processor in
// turn and ask. That is what query_topology() does; it restores the original
// affinity afterwards.
//
// Where the topology is ambiguous the map says so rather than guessing, which
// spec §4.4 asks for explicitly.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace postmortem::platform {

struct LogicalProcessor {
    unsigned group = 0;            // processor group
    unsigned index_in_group = 0;
    unsigned os_index = 0;         // flat index across groups

    std::uint32_t apic_id = 0;     // x2APIC where available, else the 8-bit ID
    bool apic_id_is_x2 = false;

    std::optional<unsigned> core_id;      // physical core within the package
    std::optional<unsigned> thread_id;    // SMT thread within the core
    std::optional<unsigned> package_id;
    std::optional<unsigned> l3_complex;   // CCX/CCD on AMD, cluster on Intel

    // Intel hybrid parts only (CPUID leaf 0x1A).
    std::optional<bool> is_performance_core;

    [[nodiscard]] std::string describe() const;
};

struct TopologyMap {
    bool available = false;
    std::string error;

    std::vector<LogicalProcessor> processors;
    unsigned physical_cores = 0;
    unsigned l3_complexes = 0;
    bool hybrid = false;
    std::string vendor;

    // Anything the enumeration could not establish, phrased for the user.
    std::vector<std::string> caveats;

    [[nodiscard]] const LogicalProcessor* find_by_apic_id(std::uint32_t apic_id) const;
};

[[nodiscard]] TopologyMap query_topology();

}  // namespace postmortem::platform
