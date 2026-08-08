// Windows Event Log access (spec §4.1).
//
// Uses EvtQuery / EvtNext / EvtRender directly, never wevtutil or PowerShell -
// shelling out would be slower, would depend on execution policy, and would
// make the .evtx path impossible to do properly.
//
// Offline analysis is a first-class path: the same query runs against the live
// System channel or a saved .evtx via EvtQueryFilePath, because "people export
// logs and send them to someone else for analysis".

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "core/events/event.hpp"

namespace postmortem::platform {

struct EventQuery {
    // Empty means the live System channel; otherwise a path to a .evtx file.
    std::string evtx_path;

    // Providers to include. Empty means every provider on the channel.
    std::vector<std::string> providers;

    // Only events at or after this Unix timestamp. 0 means no lower bound.
    std::int64_t since = 0;

    // Stop after this many events; 0 means unlimited. A guard against a log
    // with a million records, not a feature.
    std::size_t limit = 0;
};

struct EventQueryResult {
    bool ok = false;
    std::vector<events::Event> events;
    std::string error;

    // Non-fatal problems: a record that would not render, a provider absent
    // from this machine. Reported rather than swallowed.
    std::vector<std::string> warnings;
};

[[nodiscard]] EventQueryResult query_events(const EventQuery& query);

// Live push subscription for `pm watch` (spec §4.7). The callback runs on the
// subscription's thread. Returns when `keep_going` returns false, which the
// caller wires to its Ctrl+C handler.
using EventCallback = std::function<void(const events::Event&)>;

struct SubscriptionResult {
    bool ok = false;
    std::string error;
};

[[nodiscard]] SubscriptionResult subscribe_events(const std::vector<std::string>& providers,
                                                  const EventCallback& on_event,
                                                  const std::function<bool()>& keep_going);

// True when the process can read the Security channel and mutate machine
// state - i.e. is running elevated. Read-only WHEA queries do not need it
// (spec §2), but the mitigations in §4.9 do.
[[nodiscard]] bool is_elevated();

}  // namespace postmortem::platform
