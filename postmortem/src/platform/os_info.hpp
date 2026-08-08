#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace postmortem::platform {

struct OsInfo {
    std::string product_name;     // e.g. "Windows 11 Pro"
    std::string display_version;  // e.g. "24H2"
    std::string edition_id;
    std::string build_lab;        // BuildLabEx, shown with --verbose

    unsigned major = 0;
    unsigned minor = 0;
    unsigned build = 0;
    unsigned ubr = 0;             // update build revision, the ".xxxx" suffix

    // Unix seconds, UTC. Spec §4.6 correlates first-seen incidents against the
    // install date, so it is collected here rather than derived later.
    std::optional<std::int64_t> install_date;

    std::uint64_t uptime_ms = 0;
    std::int64_t boot_time = 0;   // Unix seconds, UTC
    std::int64_t now = 0;         // Unix seconds, UTC
};

[[nodiscard]] OsInfo query_os_info();

// "2026-08-08 15:04:21" in local time. Empty for a non-representable value.
[[nodiscard]] std::string format_local_time(std::int64_t unix_seconds);

// "12d 4h 33m" - coarse on purpose; uptime is context, not evidence.
[[nodiscard]] std::string format_duration(std::uint64_t milliseconds);

}  // namespace postmortem::platform
