#include "platform/console.hpp"

#include <windows.h>

#include <shellapi.h>

#include <cstdlib>

#include "platform/strings.hpp"

namespace postmortem::platform {
namespace {

bool no_color_env_set() {
    // no-color.org: any non-empty value disables colour.
    std::size_t size = 0;
    if (::getenv_s(&size, nullptr, 0, "NO_COLOR") != 0) return false;
    return size > 1;   // size includes the terminating NUL
}

}  // namespace

bool prepare_console(bool no_color_flag) {
    // Do this regardless of colour: the brand and firmware strings can contain
    // non-ASCII bytes and would otherwise print as mojibake.
    ::SetConsoleOutputCP(CP_UTF8);

    if (no_color_flag) return false;
    if (no_color_env_set()) return false;

    const HANDLE stdout_handle = ::GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdout_handle == nullptr || stdout_handle == INVALID_HANDLE_VALUE) return false;

    DWORD mode = 0;
    // GetConsoleMode fails for a pipe or a redirect to a file, which is
    // exactly when colour should be suppressed.
    if (::GetConsoleMode(stdout_handle, &mode) == FALSE) return false;

    if ((mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0) return true;
    return ::SetConsoleMode(stdout_handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != FALSE;
}

std::vector<std::string> command_line_arguments() {
    int count = 0;
    wchar_t** argv = ::CommandLineToArgvW(::GetCommandLineW(), &count);
    if (argv == nullptr) return {};

    std::vector<std::string> arguments;
    arguments.reserve(count > 0 ? static_cast<std::size_t>(count - 1) : 0);
    for (int i = 1; i < count; ++i) {
        arguments.push_back(to_utf8(argv[i]));
    }

    ::LocalFree(argv);
    return arguments;
}

}  // namespace postmortem::platform
