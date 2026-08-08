// Power-scheme settings via powrprof (spec §4.9).
//
// Everything here is documented Win32: PowerEnumerate, PowerReadACValueIndex,
// PowerWriteACValueIndex and friends. No registry pokes at the power keys, and
// no driver - spec §2.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace postmortem::platform {

struct PowerScheme {
    std::string guid;    // canonical text form
    std::string name;
    bool active = false;
};

[[nodiscard]] std::vector<PowerScheme> list_power_schemes();
[[nodiscard]] std::optional<PowerScheme> active_power_scheme();

// One processor-subgroup setting, identified by its power-setting GUID.
struct PowerSettingValue {
    bool ok = false;
    std::uint32_t ac = 0;
    std::uint32_t dc = 0;
    std::string error;
};

// The setting GUIDs spec §4.9 names, as text so callers stay free of the
// Windows GUID type.
namespace power_settings {
inline constexpr const char* kProcThrottleMaximum = "bc5038f7-23e0-4960-96da-33abaf5935ec";
inline constexpr const char* kProcThrottleMinimum = "893dee8e-2bef-41e0-89c6-b55d0929964c";
inline constexpr const char* kIdleDisable = "5d76a2ca-e8c0-402f-a133-2158492d58ad";
inline constexpr const char* kIdlePromoteThreshold = "7b224883-b3cc-4d79-819f-8374152cbe7c";
inline constexpr const char* kIdleDemoteThreshold = "4b92d758-5a24-4851-a470-815d78aee119";
}  // namespace power_settings

[[nodiscard]] PowerSettingValue read_processor_setting(const std::string& scheme_guid,
                                                       const std::string& setting_guid);

struct PowerWriteResult {
    bool ok = false;
    std::string error;
};

[[nodiscard]] PowerWriteResult write_processor_setting(const std::string& scheme_guid,
                                                       const std::string& setting_guid,
                                                       std::uint32_t ac, std::uint32_t dc);

// Makes hidden processor settings visible in the Control Panel UI. Not needed
// to write them, but without it a user cannot see what the tool changed.
void unhide_processor_setting(const std::string& setting_guid);

// Re-applies the active scheme so a written value takes effect immediately.
[[nodiscard]] PowerWriteResult reapply_active_scheme();

// --- Verification (spec §4.9) ----------------------------------------------
//
// "On builds where CPPC overrides PROCTHROTTLEMAX, the setting is silently
// ignored - sample actual frequencies briefly and warn if they still exceed
// the cap."

struct FrequencySample {
    bool ok = false;
    std::string error;
    unsigned max_mhz = 0;          // highest observed across all processors
    unsigned nominal_mhz = 0;      // the firmware-reported base clock
    unsigned observed_percent = 0; // max_mhz as a percentage of nominal
};

[[nodiscard]] FrequencySample sample_frequencies(unsigned milliseconds = 400);

}  // namespace postmortem::platform
