#include "platform/power.hpp"

#include <windows.h>

// WIN32_LEAN_AND_MEAN leaves out the COM headers, but StringFromGUID2 and
// CLSIDFromString are the documented way to move between a GUID and its text
// form, and powerbase.h is where ProcessorPowerInformation lives.
#include <objbase.h>
#include <powerbase.h>
#include <powrprof.h>

#include <algorithm>
#include <cctype>
#include <vector>

#include "platform/strings.hpp"

namespace postmortem::platform {
namespace {

// ProcessorPowerInformation is documented as living in powerbase.h but is
// not actually declared in any shipped SDK header - a long-standing gap.
// Declaring it here is the usual remedy; the layout is from the
// CallNtPowerInformation documentation for ProcessorInformation.
struct ProcessorPowerInformation {
    ULONG Number;
    ULONG MaxMhz;
    ULONG CurrentMhz;
    ULONG MhzLimit;
    ULONG MaxIdleState;
    ULONG CurrentIdleState;
};

// GUID_PROCESSOR_SETTINGS_SUBGROUP, the subgroup every setting below lives in.
constexpr GUID kProcessorSubgroup = {
    0x54533251, 0x82be, 0x4824, {0x96, 0xc1, 0x47, 0xb6, 0x0b, 0x74, 0x0d, 0x00}};

std::string guid_to_string(const GUID& guid) {
    wchar_t buffer[64] = {};
    const int written = ::StringFromGUID2(guid, buffer, static_cast<int>(std::size(buffer)));
    if (written <= 0) return {};

    std::string text = to_utf8(std::wstring_view(buffer, static_cast<std::size_t>(written - 1)));
    // StringFromGUID2 wraps in braces; the canonical form here does not.
    if (text.size() >= 2 && text.front() == '{' && text.back() == '}') {
        text = text.substr(1, text.size() - 2);
    }
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

std::optional<GUID> guid_from_string(const std::string& text) {
    const std::wstring wide = to_utf16("{" + text + "}");
    GUID guid{};
    if (::CLSIDFromString(wide.c_str(), &guid) != NOERROR) return std::nullopt;
    return guid;
}

std::string scheme_name(const GUID& scheme) {
    DWORD size = 0;
    if (::PowerReadFriendlyName(nullptr, &scheme, nullptr, nullptr, nullptr, &size) !=
        ERROR_SUCCESS) {
        return {};
    }
    std::vector<UCHAR> buffer(size + sizeof(wchar_t), 0);
    if (::PowerReadFriendlyName(nullptr, &scheme, nullptr, nullptr, buffer.data(), &size) !=
        ERROR_SUCCESS) {
        return {};
    }
    return trim(to_utf8(reinterpret_cast<const wchar_t*>(buffer.data())));
}

}  // namespace

std::vector<PowerScheme> list_power_schemes() {
    std::vector<PowerScheme> schemes;

    GUID* active = nullptr;
    std::string active_guid;
    if (::PowerGetActiveScheme(nullptr, &active) == ERROR_SUCCESS && active != nullptr) {
        active_guid = guid_to_string(*active);
        ::LocalFree(active);
    }

    for (ULONG index = 0;; ++index) {
        GUID scheme{};
        DWORD size = sizeof(scheme);
        const DWORD status = ::PowerEnumerate(nullptr, nullptr, nullptr, ACCESS_SCHEME, index,
                                              reinterpret_cast<UCHAR*>(&scheme), &size);
        if (status != ERROR_SUCCESS) break;

        PowerScheme entry;
        entry.guid = guid_to_string(scheme);
        entry.name = scheme_name(scheme);
        entry.active = !active_guid.empty() && entry.guid == active_guid;
        schemes.push_back(std::move(entry));
    }

    return schemes;
}

std::optional<PowerScheme> active_power_scheme() {
    for (PowerScheme& scheme : list_power_schemes()) {
        if (scheme.active) return scheme;
    }
    return std::nullopt;
}

PowerSettingValue read_processor_setting(const std::string& scheme_guid,
                                         const std::string& setting_guid) {
    PowerSettingValue value;

    const auto scheme = guid_from_string(scheme_guid);
    const auto setting = guid_from_string(setting_guid);
    if (!scheme.has_value() || !setting.has_value()) {
        value.error = "malformed GUID";
        return value;
    }

    DWORD ac = 0;
    DWORD dc = 0;
    const DWORD ac_status =
        ::PowerReadACValueIndex(nullptr, &*scheme, &kProcessorSubgroup, &*setting, &ac);
    const DWORD dc_status =
        ::PowerReadDCValueIndex(nullptr, &*scheme, &kProcessorSubgroup, &*setting, &dc);

    if (ac_status != ERROR_SUCCESS && dc_status != ERROR_SUCCESS) {
        // Common and not an error: many processor settings do not exist on
        // machines whose driver does not expose them.
        value.error = "this setting is not present on this machine";
        return value;
    }

    value.ok = true;
    value.ac = ac;
    value.dc = dc;
    return value;
}

PowerWriteResult write_processor_setting(const std::string& scheme_guid,
                                         const std::string& setting_guid, std::uint32_t ac,
                                         std::uint32_t dc) {
    PowerWriteResult result;

    const auto scheme = guid_from_string(scheme_guid);
    const auto setting = guid_from_string(setting_guid);
    if (!scheme.has_value() || !setting.has_value()) {
        result.error = "malformed GUID";
        return result;
    }

    const DWORD ac_status =
        ::PowerWriteACValueIndex(nullptr, &*scheme, &kProcessorSubgroup, &*setting, ac);
    if (ac_status != ERROR_SUCCESS) {
        result.error = "PowerWriteACValueIndex failed with " + std::to_string(ac_status);
        if (ac_status == ERROR_ACCESS_DENIED) {
            result.error += " (this needs an elevated process)";
        }
        return result;
    }

    const DWORD dc_status =
        ::PowerWriteDCValueIndex(nullptr, &*scheme, &kProcessorSubgroup, &*setting, dc);
    if (dc_status != ERROR_SUCCESS) {
        result.error = "the AC value was written but PowerWriteDCValueIndex failed with " +
                       std::to_string(dc_status);
        return result;
    }

    result.ok = true;
    return result;
}

void unhide_processor_setting(const std::string& setting_guid) {
    const auto setting = guid_from_string(setting_guid);
    if (!setting.has_value()) return;

    // Attribute bit 1 is POWER_ATTRIBUTE_HIDE; clearing it makes the setting
    // visible in the advanced power options UI.
    ::PowerWriteSettingAttributes(&kProcessorSubgroup, &*setting, 0);
}

PowerWriteResult reapply_active_scheme() {
    PowerWriteResult result;

    GUID* active = nullptr;
    if (::PowerGetActiveScheme(nullptr, &active) != ERROR_SUCCESS || active == nullptr) {
        result.error = "cannot read the active power scheme";
        return result;
    }

    const DWORD status = ::PowerSetActiveScheme(nullptr, active);
    ::LocalFree(active);

    if (status != ERROR_SUCCESS) {
        result.error = "PowerSetActiveScheme failed with " + std::to_string(status);
        return result;
    }
    result.ok = true;
    return result;
}

FrequencySample sample_frequencies(unsigned milliseconds) {
    FrequencySample sample;

    SYSTEM_INFO info{};
    ::GetNativeSystemInfo(&info);
    const DWORD count = info.dwNumberOfProcessors;
    if (count == 0) {
        sample.error = "no processors reported";
        return sample;
    }

    // ProcessorPowerInformation per logical processor: nominal, maximum and
    // current MHz. CallNtPowerInformation is the documented way in.
    std::vector<ProcessorPowerInformation> info_buffer(count);
    // CallNtPowerInformation returns NTSTATUS, which windows.h does not always
    // typedef; LONG is the same thing and avoids depending on which header
    // won the race.
    const auto read = [&]() -> bool {
        const LONG status = ::CallNtPowerInformation(
            ProcessorInformation, nullptr, 0, info_buffer.data(),
            static_cast<ULONG>(info_buffer.size() * sizeof(ProcessorPowerInformation)));
        return status == 0;
    };

    if (!read()) {
        sample.error = "CallNtPowerInformation(ProcessorInformation) failed";
        return sample;
    }
    sample.nominal_mhz = info_buffer.front().MaxMhz;

    // Sample a few times: a single read can land in a moment of idle and miss
    // a cap that is being ignored.
    const unsigned rounds = std::max(2u, milliseconds / 100u);
    for (unsigned round = 0; round < rounds; ++round) {
        if (!read()) break;
        for (const ProcessorPowerInformation& processor : info_buffer) {
            sample.max_mhz = std::max<unsigned>(sample.max_mhz, processor.CurrentMhz);
        }
        ::Sleep(100);
    }

    sample.ok = true;
    if (sample.nominal_mhz > 0) {
        sample.observed_percent = sample.max_mhz * 100 / sample.nominal_mhz;
    }
    return sample;
}

}  // namespace postmortem::platform
