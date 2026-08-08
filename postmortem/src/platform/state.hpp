// The mitigation state snapshot (spec §4.9).
//
// "Before mutating, snapshot the current value into
// %ProgramData%\postmortem\state.json with a timestamp. `revert` restores from
// that snapshot, not from a hardcoded default."
//
// The file is written atomically - to a temporary name, then renamed - because
// a half-written snapshot is worse than none: it would leave a machine changed
// with no record of how to change it back.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace postmortem::platform {

struct StateEntry {
    std::string mitigation;      // e.g. "max-cpu-99"
    std::string kind;            // "power" or "registry"
    std::string scope;           // power-scheme GUID, or the registry key path
    std::string scope_name;      // friendly scheme name, for display
    std::string key;             // power-setting GUID, or the value name

    bool previous_present = true;   // false when a registry value did not exist
    std::uint32_t previous_ac = 0;
    std::uint32_t previous_dc = 0;

    std::int64_t applied_at = 0;    // Unix seconds, UTC
};

struct StateLoad {
    bool ok = false;
    bool missing = false;   // no state file yet, which is not an error
    std::string error;
};

struct StateSave {
    bool ok = false;
    std::string path;
    std::string error;
};

class StateStore {
public:
    StateStore();

    [[nodiscard]] StateLoad load();
    [[nodiscard]] StateSave save() const;

    void add(const StateEntry& entry);
    void remove(std::string_view mitigation);
    [[nodiscard]] std::vector<StateEntry> entries_for(std::string_view mitigation) const;
    [[nodiscard]] const std::vector<StateEntry>& entries() const { return entries_; }

    [[nodiscard]] const std::string& path() const { return path_; }

private:
    std::string path_;
    std::vector<StateEntry> entries_;
};

// %ProgramData%\postmortem, created on demand.
[[nodiscard]] std::string state_directory();

}  // namespace postmortem::platform
