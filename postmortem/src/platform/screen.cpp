#include "platform/screen.hpp"

#include <windows.h>

#include <conio.h>

#include <cstdio>

namespace postmortem::platform {
namespace {

void write_console(const char* text, std::size_t length) {
    std::fwrite(text, 1, length, stdout);
}

void write_console(const std::string& text) {
    write_console(text.data(), text.size());
}

constexpr const char* kEnterAlternate = "\x1b[?1049h";
constexpr const char* kLeaveAlternate = "\x1b[?1049l";
constexpr const char* kHideCursor = "\x1b[?25l";
constexpr const char* kShowCursor = "\x1b[?25h";
constexpr const char* kHome = "\x1b[H";
constexpr const char* kClearToEndOfLine = "\x1b[K";
constexpr const char* kClearToEndOfScreen = "\x1b[J";

}  // namespace

Screen::~Screen() {
    leave();
}

bool Screen::enter() {
    const HANDLE handle = ::GetStdHandle(STD_OUTPUT_HANDLE);
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) return false;

    DWORD mode = 0;
    if (::GetConsoleMode(handle, &mode) == FALSE) return false;   // piped or redirected
    previous_mode_ = mode;
    had_previous_mode_ = true;

    if ((mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0) {
        if (::SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) == FALSE) {
            return false;
        }
    }

    write_console(kEnterAlternate, 8);
    write_console(kHideCursor, 6);
    std::fflush(stdout);
    active_ = true;
    return true;
}

void Screen::leave() {
    if (!active_) return;

    write_console(kShowCursor, 6);
    write_console(kLeaveAlternate, 8);
    std::fflush(stdout);
    active_ = false;

    if (had_previous_mode_) {
        const HANDLE handle = ::GetStdHandle(STD_OUTPUT_HANDLE);
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
            ::SetConsoleMode(handle, previous_mode_);
        }
        had_previous_mode_ = false;
    }
}

ScreenSize Screen::size() const {
    ScreenSize size;
    const HANDLE handle = ::GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE &&
        ::GetConsoleScreenBufferInfo(handle, &info) != FALSE) {
        size.columns = static_cast<unsigned>(info.srWindow.Right - info.srWindow.Left + 1);
        size.rows = static_cast<unsigned>(info.srWindow.Bottom - info.srWindow.Top + 1);
    }
    if (size.columns < 40) size.columns = 40;
    if (size.rows < 10) size.rows = 10;
    return size;
}

void Screen::draw(const std::string& frame) {
    // One buffered write per frame. Redrawing line by line with a clear-to-end
    // on each avoids the flash a full clear-then-draw produces.
    std::string out;
    out.reserve(frame.size() + 256);
    out += kHome;

    std::size_t start = 0;
    while (start <= frame.size()) {
        const std::size_t newline = frame.find('\n', start);
        const std::size_t end = newline == std::string::npos ? frame.size() : newline;
        out.append(frame, start, end - start);
        out += kClearToEndOfLine;
        if (newline == std::string::npos) break;
        out += "\r\n";
        start = newline + 1;
    }
    out += kClearToEndOfScreen;

    write_console(out);
    std::fflush(stdout);
}

int poll_key() {
    if (_kbhit() == 0) return 0;
    const int key = _getch();
    // Function and arrow keys arrive as a two-byte sequence; swallow the tail
    // so it is not mistaken for a command on the next poll.
    if (key == 0 || key == 0xE0) {
        if (_kbhit() != 0) _getch();
        return 0;
    }
    return key;
}

}  // namespace postmortem::platform
