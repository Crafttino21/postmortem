// Full-screen terminal control for `pm live`.
//
// Uses VT sequences rather than the console screen-buffer API: the console
// already has ENABLE_VIRTUAL_TERMINAL_PROCESSING turned on for colour, VT
// works in Windows Terminal and the classic console alike, and it keeps the
// rendering side free of Win32.
//
// The alternate screen buffer means the user's scrollback survives - `pm live`
// takes over the screen, and on exit the terminal is exactly as it was.

#pragma once

#include <string>

namespace postmortem::platform {

struct ScreenSize {
    unsigned columns = 80;
    unsigned rows = 25;
};

class Screen {
public:
    Screen() = default;
    ~Screen();

    Screen(const Screen&) = delete;
    Screen& operator=(const Screen&) = delete;

    // Switches to the alternate buffer and hides the cursor. Safe to call when
    // stdout is redirected; enter() then returns false and the caller should
    // fall back to plain line output.
    [[nodiscard]] bool enter();
    void leave();

    [[nodiscard]] ScreenSize size() const;

    // Draws a frame. Each line is cleared to the end as it is written and the
    // rest of the screen is cleared once at the bottom, so there is no flicker
    // and no need to clear before drawing.
    void draw(const std::string& frame);

private:
    bool active_ = false;
    unsigned long previous_mode_ = 0;
    bool had_previous_mode_ = false;
};

// Non-blocking single-key read. Returns 0 when nothing is waiting.
[[nodiscard]] int poll_key();

}  // namespace postmortem::platform
