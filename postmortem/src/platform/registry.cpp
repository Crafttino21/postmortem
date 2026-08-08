#include "platform/registry.hpp"

#include <windows.h>

#include <cstring>
#include <utility>

#include "platform/strings.hpp"

namespace postmortem::platform::registry {
namespace {

HKEY native_hive(Hive hive) {
    switch (hive) {
        case Hive::CurrentUser:  return HKEY_CURRENT_USER;
        case Hive::LocalMachine: break;
    }
    return HKEY_LOCAL_MACHINE;
}

// Reads a value of any type into a raw byte buffer. Returns nullopt on any
// failure, including "key or value absent", which is an expected outcome.
std::optional<std::pair<DWORD, std::vector<BYTE>>> read_raw(Hive hive, const wchar_t* subkey,
                                                            const wchar_t* value) {
    HKEY key = nullptr;
    // KEY_WOW64_64KEY: pm.exe is x64 so this is already the 64-bit view, but
    // stating it keeps the read correct if a 32-bit build is ever produced.
    if (::RegOpenKeyExW(native_hive(hive), subkey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) !=
        ERROR_SUCCESS) {
        return std::nullopt;
    }

    DWORD type = 0;
    DWORD size = 0;
    LSTATUS status = ::RegQueryValueExW(key, value, nullptr, &type, nullptr, &size);
    if (status != ERROR_SUCCESS) {
        ::RegCloseKey(key);
        return std::nullopt;
    }

    // Slack at the end: RegQueryValueExW does not guarantee that a string
    // value in the registry is NUL-terminated, and an odd byte count would
    // otherwise leave a partial wchar_t at the boundary.
    std::vector<BYTE> buffer(size + sizeof(wchar_t), 0);
    DWORD read_size = size;
    status = ::RegQueryValueExW(key, value, nullptr, &type, buffer.data(), &read_size);
    ::RegCloseKey(key);
    if (status != ERROR_SUCCESS) return std::nullopt;

    buffer.resize(read_size);
    return std::make_pair(type, std::move(buffer));
}

}  // namespace

std::optional<std::string> read_string(Hive hive, const wchar_t* subkey, const wchar_t* value) {
    const auto raw = read_raw(hive, subkey, value);
    if (!raw.has_value()) return std::nullopt;

    const auto& [type, buffer] = *raw;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return std::nullopt;
    if (buffer.size() < sizeof(wchar_t)) return std::string{};

    const auto* chars = reinterpret_cast<const wchar_t*>(buffer.data());
    std::size_t length = buffer.size() / sizeof(wchar_t);
    while (length > 0 && chars[length - 1] == L'\0') --length;  // drop the terminator

    return trim(to_utf8(std::wstring_view(chars, length)));
}

std::optional<std::uint32_t> read_dword(Hive hive, const wchar_t* subkey, const wchar_t* value) {
    const auto raw = read_raw(hive, subkey, value);
    if (!raw.has_value()) return std::nullopt;

    const auto& [type, buffer] = *raw;
    if (type != REG_DWORD || buffer.size() < sizeof(std::uint32_t)) return std::nullopt;

    std::uint32_t result = 0;
    std::memcpy(&result, buffer.data(), sizeof(result));
    return result;
}

bool write_dword(Hive hive, const wchar_t* subkey, const wchar_t* value, std::uint32_t data) {
    HKEY key = nullptr;
    if (::RegOpenKeyExW(native_hive(hive), subkey, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key) !=
        ERROR_SUCCESS) {
        return false;
    }

    const LSTATUS status = ::RegSetValueExW(key, value, 0, REG_DWORD,
                                            reinterpret_cast<const BYTE*>(&data), sizeof(data));
    ::RegCloseKey(key);
    return status == ERROR_SUCCESS;
}

std::optional<std::vector<std::uint8_t>> read_binary(Hive hive, const wchar_t* subkey,
                                                     const wchar_t* value) {
    const auto raw = read_raw(hive, subkey, value);
    if (!raw.has_value()) return std::nullopt;

    const auto& [type, buffer] = *raw;
    if (type != REG_BINARY) return std::nullopt;
    return std::vector<std::uint8_t>(buffer.begin(), buffer.end());
}

}  // namespace postmortem::platform::registry
