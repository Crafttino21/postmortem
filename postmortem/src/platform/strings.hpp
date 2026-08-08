#pragma once

#include <string>
#include <string_view>

namespace postmortem::platform {

// Win32 gives us UTF-16; everything above the platform layer speaks UTF-8.
[[nodiscard]] std::string to_utf8(std::wstring_view text);
[[nodiscard]] std::wstring to_utf16(std::string_view text);

// Trims ASCII whitespace from both ends. Firmware strings are routinely
// padded ("To Be Filled By O.E.M.   ").
[[nodiscard]] std::string trim(std::string_view text);

// True for the placeholder values OEMs leave in SMBIOS fields.
[[nodiscard]] bool is_firmware_placeholder(std::string_view text);

}  // namespace postmortem::platform
