#include "platform/strings.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cctype>

namespace postmortem::platform {
namespace {

bool equals_ignore_case(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const auto ca = static_cast<unsigned char>(a[i]);
        const auto cb = static_cast<unsigned char>(b[i]);
        if (std::tolower(ca) != std::tolower(cb)) return false;
    }
    return true;
}

}  // namespace

std::string to_utf8(std::wstring_view text) {
    if (text.empty()) return {};
    const int needed = ::WideCharToMultiByte(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};

    std::string out(static_cast<std::size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(),
                          needed, nullptr, nullptr);
    return out;
}

std::wstring to_utf16(std::string_view text) {
    if (text.empty()) return {};
    const int needed = ::MultiByteToWideChar(CP_UTF8, 0, text.data(),
                                             static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0) return {};

    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(),
                          needed);
    return out;
}

std::string trim(std::string_view text) {
    const auto is_space = [](char c) {
        return std::isspace(static_cast<unsigned char>(c)) != 0;
    };
    std::size_t begin = 0;
    std::size_t end = text.size();
    while (begin < end && is_space(text[begin])) ++begin;
    while (end > begin && is_space(text[end - 1])) --end;
    return std::string(text.substr(begin, end - begin));
}

bool is_firmware_placeholder(std::string_view text) {
    static constexpr std::array<std::string_view, 8> kPlaceholders{
        "To Be Filled By O.E.M.",
        "To be filled by O.E.M.",
        "System manufacturer",
        "System Product Name",
        "Default string",
        "Not Specified",
        "Not Applicable",
        "None",
    };
    const std::string trimmed = trim(text);
    if (trimmed.empty()) return true;
    return std::any_of(kPlaceholders.begin(), kPlaceholders.end(),
                       [&](std::string_view candidate) {
                           return equals_ignore_case(trimmed, candidate);
                       });
}

}  // namespace postmortem::platform
