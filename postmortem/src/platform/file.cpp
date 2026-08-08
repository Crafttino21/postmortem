#include "platform/file.hpp"

#include <windows.h>

#include <algorithm>

#include "platform/strings.hpp"

namespace postmortem::platform {
namespace {

// A CPER record is a few kilobytes. Anything remotely this large is a mistake
// - a wrong path, or an .evtx passed where a blob was meant - and reading it
// into memory would be the wrong response either way.
constexpr std::uint64_t kMaxSize = 64ull * 1024 * 1024;

std::string last_error_text() {
    const DWORD code = ::GetLastError();
    LPWSTR buffer = nullptr;
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::string message;
    if (length > 0 && buffer != nullptr) {
        message = trim(to_utf8(std::wstring_view(buffer, length)));
    }
    if (buffer != nullptr) ::LocalFree(buffer);

    if (message.empty()) message = "error " + std::to_string(code);
    return message;
}

}  // namespace

FileResult read_file(const std::string& utf8_path) {
    FileResult result;

    const std::wstring path = to_utf16(utf8_path);
    const HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        result.error = "cannot open '" + utf8_path + "': " + last_error_text();
        return result;
    }

    LARGE_INTEGER size{};
    if (::GetFileSizeEx(file, &size) == FALSE) {
        result.error = "cannot size '" + utf8_path + "': " + last_error_text();
        ::CloseHandle(file);
        return result;
    }
    if (static_cast<std::uint64_t>(size.QuadPart) > kMaxSize) {
        result.error = "'" + utf8_path + "' is " + std::to_string(size.QuadPart) +
                       " bytes, far larger than any error record; refusing to read it";
        ::CloseHandle(file);
        return result;
    }

    result.bytes.resize(static_cast<std::size_t>(size.QuadPart));
    std::size_t total = 0;
    while (total < result.bytes.size()) {
        const DWORD want = static_cast<DWORD>(
            std::min<std::uint64_t>(result.bytes.size() - total, 1u << 20));
        DWORD read = 0;
        if (::ReadFile(file, result.bytes.data() + total, want, &read, nullptr) == FALSE) {
            result.error = "cannot read '" + utf8_path + "': " + last_error_text();
            ::CloseHandle(file);
            return result;
        }
        if (read == 0) break;   // shorter than advertised; use what arrived
        total += read;
    }
    result.bytes.resize(total);

    ::CloseHandle(file);
    result.ok = true;
    return result;
}

}  // namespace postmortem::platform
