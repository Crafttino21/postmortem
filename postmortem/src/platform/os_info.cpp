#include "platform/os_info.hpp"

#include <windows.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <string_view>

#include "platform/registry.hpp"
#include "platform/strings.hpp"

namespace postmortem::platform {
namespace {

constexpr const wchar_t* kCurrentVersionKey =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

// GetVersionEx is shimmed by application compatibility and lies unless the
// binary carries a matching manifest. RtlGetVersion is the documented way to
// get the real numbers; it is exported by ntdll and always present.
bool query_real_version(OsInfo& info) {
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);

    const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) return false;

    const auto rtl_get_version =
        reinterpret_cast<RtlGetVersionFn>(
            reinterpret_cast<void*>(::GetProcAddress(ntdll, "RtlGetVersion")));
    if (rtl_get_version == nullptr) return false;

    RTL_OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    if (rtl_get_version(&version) != 0) return false;

    info.major = version.dwMajorVersion;
    info.minor = version.dwMinorVersion;
    info.build = version.dwBuildNumber;
    return true;
}

// The registry ProductName still reads "Windows 10 ..." on Windows 11; the
// build number is the only reliable discriminator. Correct it rather than
// printing something the user knows is wrong.
std::string normalise_product_name(std::string name, unsigned build) {
    constexpr unsigned kFirstWindows11Build = 22000;
    if (build < kFirstWindows11Build) return name;

    constexpr std::string_view kWindows10 = "Windows 10";
    if (name.rfind(kWindows10.data(), 0, kWindows10.size()) == 0) {
        name.replace(0, kWindows10.size(), "Windows 11");
    }
    return name;
}

}  // namespace

OsInfo query_os_info() {
    OsInfo info;
    query_real_version(info);

    using registry::Hive;
    if (const auto value = registry::read_string(Hive::LocalMachine, kCurrentVersionKey,
                                                 L"ProductName")) {
        info.product_name = *value;
    }
    if (const auto value = registry::read_string(Hive::LocalMachine, kCurrentVersionKey,
                                                 L"DisplayVersion")) {
        info.display_version = *value;
    }
    if (const auto value = registry::read_string(Hive::LocalMachine, kCurrentVersionKey,
                                                 L"EditionID")) {
        info.edition_id = *value;
    }
    if (const auto value = registry::read_string(Hive::LocalMachine, kCurrentVersionKey,
                                                 L"BuildLabEx")) {
        info.build_lab = *value;
    }
    if (const auto value = registry::read_dword(Hive::LocalMachine, kCurrentVersionKey, L"UBR")) {
        info.ubr = *value;
    }
    if (info.build == 0) {
        if (const auto value = registry::read_string(Hive::LocalMachine, kCurrentVersionKey,
                                                     L"CurrentBuildNumber")) {
            info.build = static_cast<unsigned>(std::strtoul(value->c_str(), nullptr, 10));
        }
    }
    // REG_DWORD holding Unix seconds, UTC.
    if (const auto value = registry::read_dword(Hive::LocalMachine, kCurrentVersionKey,
                                                L"InstallDate")) {
        info.install_date = static_cast<std::int64_t>(*value);
    }

    info.product_name = normalise_product_name(std::move(info.product_name), info.build);

    // GetTickCount64 is biased by sleep and hibernation - i.e. it counts wall
    // time since the machine started, which is what "uptime" should mean for
    // crash correlation. QueryUnbiasedInterruptTime deliberately does not.
    info.uptime_ms = ::GetTickCount64();

    const auto now = std::chrono::system_clock::now();
    info.now = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    info.boot_time = info.now - static_cast<std::int64_t>(info.uptime_ms / 1000);

    return info;
}

std::string format_local_time(std::int64_t unix_seconds) {
    const auto value = static_cast<std::time_t>(unix_seconds);
    std::tm local{};
    if (::localtime_s(&local, &value) != 0) return {};

    std::array<char, 32> buffer{};
    const std::size_t written =
        std::strftime(buffer.data(), buffer.size(), "%Y-%m-%d %H:%M:%S", &local);
    if (written == 0) return {};
    return std::string(buffer.data(), written);
}

std::string format_duration(std::uint64_t milliseconds) {
    const std::uint64_t total_minutes = milliseconds / 60000ull;
    const std::uint64_t days = total_minutes / (60 * 24);
    const std::uint64_t hours = (total_minutes / 60) % 24;
    const std::uint64_t minutes = total_minutes % 60;

    std::string out;
    if (days > 0) out += std::to_string(days) + "d ";
    if (days > 0 || hours > 0) out += std::to_string(hours) + "h ";
    out += std::to_string(minutes) + "m";
    return out;
}

}  // namespace postmortem::platform
