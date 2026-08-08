// The sampled-stack and memory-watch renderers, plus the sub-second duration
// parsing they depend on. All pure - no ETW session, no target process.

#include <cstdint>
#include <string>
#include <vector>

#include "check.hpp"
#include "core/input/values.hpp"
#include "core/render/watch_view.hpp"
#include "core/text/table.hpp"

using postmortem::render::HotStack;
using postmortem::render::MemoryWatch;
using postmortem::render::StackFrameLine;
using postmortem::render::StackSnapshot;
using postmortem::text::Style;

namespace {

StackSnapshot sample_stacks() {
    StackSnapshot snapshot;
    snapshot.total_samples = 4180;
    snapshot.kernel_samples = 2590;
    snapshot.user_samples = 1590;
    snapshot.symbols_available = true;
    snapshot.depth = 4;

    HotStack idle;
    idle.count = 1204;
    idle.share_percent = 28.8;
    idle.process_id = 0;
    idle.process_name = "System";
    idle.frames = {StackFrameLine{"ntoskrnl!KiIdleLoop", true},
                   StackFrameLine{"ntoskrnl!KiIdleSchedule", true}};
    snapshot.stacks.push_back(idle);

    HotStack user;
    user.count = 418;
    user.share_percent = 10.0;
    user.process_id = 4812;
    user.process_name = "myapp.exe";
    user.frames = {StackFrameLine{"myapp!compute_hash+0x2c", false},
                   StackFrameLine{"myapp!worker_loop+0x118", false},
                   StackFrameLine{"kernel32!BaseThreadInitThunk+0x1d", false}};
    snapshot.stacks.push_back(user);

    return snapshot;
}

MemoryWatch sample_watch(std::size_t length = 32) {
    MemoryWatch watch;
    watch.process_id = 4812;
    watch.process_name = "explorer.exe";
    watch.address = 0x7FFE0000;
    watch.clock = "2026-08-08 19:15:51";
    watch.ticks = 8;
    watch.bytes.assign(length, 0xAB);
    watch.readable = length;
    watch.changed_now.assign(length, false);
    watch.change_counts.assign(length, 0);
    return watch;
}

std::size_t count_lines(const std::string& text) {
    std::size_t lines = 0;
    for (const char c : text) {
        if (c == '\n') ++lines;
    }
    return lines;
}

}  // namespace

// ---------------------------------------------------------------------------
// Sampled stacks
// ---------------------------------------------------------------------------

PM_TEST(stack_frame_shows_counts_shares_and_frames) {
    const std::string frame =
        postmortem::render::stack_frame(sample_stacks(), Style::plain(), 120, 40);

    PM_CHECK(frame.find("4180 samples") != std::string::npos);
    PM_CHECK(frame.find("kernel 62%") != std::string::npos);
    PM_CHECK(frame.find("user 38%") != std::string::npos);
    PM_CHECK(frame.find("ntoskrnl!KiIdleLoop") != std::string::npos);
    PM_CHECK(frame.find("myapp.exe (4812)") != std::string::npos);
    PM_CHECK(frame.find("myapp!compute_hash+0x2c") != std::string::npos);
}

PM_TEST(stack_frame_honours_the_depth_limit) {
    StackSnapshot snapshot = sample_stacks();
    snapshot.depth = 1;
    const std::string frame =
        postmortem::render::stack_frame(snapshot, Style::plain(), 120, 40);

    // Only the innermost frame of each stack survives.
    PM_CHECK(frame.find("myapp!compute_hash+0x2c") != std::string::npos);
    PM_CHECK(frame.find("myapp!worker_loop+0x118") == std::string::npos);
}

PM_TEST(stack_frame_admits_when_nothing_was_sampled) {
    StackSnapshot snapshot;
    const std::string frame =
        postmortem::render::stack_frame(snapshot, Style::plain(), 120, 40);
    PM_CHECK(frame.find("no samples yet") != std::string::npos);
}

PM_TEST(stack_frame_reports_dropped_samples_rather_than_hiding_them) {
    // A truncated profile that looks complete is worse than one that says so.
    StackSnapshot snapshot = sample_stacks();
    snapshot.dropped = 91;
    const std::string frame =
        postmortem::render::stack_frame(snapshot, Style::plain(), 120, 40);
    PM_CHECK(frame.find("91 sample(s) dropped") != std::string::npos);
}

PM_TEST(stack_frame_says_when_no_symbols_resolved) {
    StackSnapshot snapshot = sample_stacks();
    snapshot.symbols_available = false;
    const std::string frame =
        postmortem::render::stack_frame(snapshot, Style::plain(), 120, 40);
    PM_CHECK(frame.find("no function names resolved") != std::string::npos);
    // And it must be explicit that no symbol server is contacted.
    PM_CHECK(frame.find("symbol server") != std::string::npos);
}

PM_TEST(stack_frame_never_exceeds_the_window) {
    StackSnapshot snapshot = sample_stacks();
    for (int i = 0; i < 40; ++i) snapshot.stacks.push_back(snapshot.stacks.front());

    for (const unsigned rows : {12u, 24u, 50u}) {
        const std::string frame =
            postmortem::render::stack_frame(snapshot, Style::plain(), 120, rows);
        PM_CHECK(count_lines(frame) < rows);
    }
}

// ---------------------------------------------------------------------------
// Memory watch
// ---------------------------------------------------------------------------

PM_TEST(memory_frame_renders_hex_and_ascii) {
    MemoryWatch watch = sample_watch();
    watch.bytes[0] = 'C';
    watch.bytes[1] = 'P';
    watch.bytes[2] = 'E';
    watch.bytes[3] = 'R';

    const std::string frame =
        postmortem::render::memory_frame(watch, Style::plain(), 100, 40);
    PM_CHECK(frame.find("explorer.exe (4812)") != std::string::npos);
    PM_CHECK(frame.find("0x000000007FFE0000") != std::string::npos);
    PM_CHECK(frame.find("43 50 45 52") != std::string::npos);   // the hex
    PM_CHECK(frame.find("CPER") != std::string::npos);          // the ascii gutter
    PM_CHECK(frame.find("tick 8") != std::string::npos);
}

PM_TEST(memory_frame_counts_changes) {
    MemoryWatch watch = sample_watch();
    watch.changed_now[2] = true;
    watch.changed_now[5] = true;
    watch.change_counts[2] = 4;
    watch.change_counts[5] = 1;
    watch.change_counts[9] = 7;   // changed earlier, not this tick

    const std::string frame =
        postmortem::render::memory_frame(watch, Style::plain(), 100, 40);
    PM_CHECK(frame.find("2 byte(s) changed this tick") != std::string::npos);
    PM_CHECK(frame.find("3 of 32 have ever changed") != std::string::npos);
}

PM_TEST(memory_frame_marks_unreadable_bytes) {
    // A region can be partly decommitted; showing zeroes there would be a lie.
    MemoryWatch watch = sample_watch();
    watch.readable = 8;

    const std::string frame =
        postmortem::render::memory_frame(watch, Style::plain(), 100, 40);
    PM_CHECK(frame.find("??") != std::string::npos);
    PM_CHECK(frame.find("only 8 byte(s) readable") != std::string::npos);
}

PM_TEST(memory_frame_reports_a_failed_read) {
    MemoryWatch watch = sample_watch();
    watch.error = "the region is no longer readable";

    const std::string frame =
        postmortem::render::memory_frame(watch, Style::plain(), 100, 40);
    PM_CHECK(frame.find("no longer readable") != std::string::npos);
}

PM_TEST(memory_frame_clips_to_the_window_and_says_so) {
    MemoryWatch watch = sample_watch(4096);
    const std::string frame =
        postmortem::render::memory_frame(watch, Style::plain(), 100, 20);

    PM_CHECK(count_lines(frame) < 20);
    PM_CHECK(frame.find("more byte(s)") != std::string::npos);
}

PM_TEST(memory_frame_colours_changed_bytes) {
    MemoryWatch watch = sample_watch();
    watch.changed_now[0] = true;

    const std::string plain =
        postmortem::render::memory_frame(watch, Style::plain(), 100, 40);
    PM_CHECK(plain.find('\x1b') == std::string::npos);

    const std::string coloured =
        postmortem::render::memory_frame(watch, Style::ansi(), 100, 40);
    PM_CHECK(coloured.find('\x1b') != std::string::npos);
}

// ---------------------------------------------------------------------------
// Sub-second durations
// ---------------------------------------------------------------------------

PM_TEST(duration_parses_milliseconds_without_confusing_them_for_minutes) {
    using postmortem::input::parse_duration;

    // The bug this guards: taking only the last character as the unit reads
    // "500ms" as 500 minutes with a stray 's', turning a half-second refresh
    // into eight hours.
    const auto ms = parse_duration("500ms");
    PM_CHECK(ms.ok);
    PM_CHECK_EQ(ms.milliseconds, std::int64_t{500});
    PM_CHECK_EQ(ms.seconds, std::int64_t{0});

    const auto minutes = parse_duration("500m");
    PM_CHECK(minutes.ok);
    PM_CHECK_EQ(minutes.milliseconds, std::int64_t{500} * 60 * 1000);
    PM_CHECK_EQ(minutes.seconds, std::int64_t{500} * 60);
}

PM_TEST(duration_keeps_the_existing_units_working) {
    using postmortem::input::parse_duration;

    PM_CHECK_EQ(parse_duration("90d").seconds, std::int64_t{90} * 86400);
    PM_CHECK_EQ(parse_duration("12h").seconds, std::int64_t{12} * 3600);
    PM_CHECK_EQ(parse_duration("30m").seconds, std::int64_t{30} * 60);
    PM_CHECK_EQ(parse_duration("45s").seconds, std::int64_t{45});
    PM_CHECK_EQ(parse_duration("2w").seconds, std::int64_t{14} * 86400);
    PM_CHECK_EQ(parse_duration("1y").seconds, std::int64_t{365} * 86400);
    // A bare number still means days.
    PM_CHECK_EQ(parse_duration("7").seconds, std::int64_t{7} * 86400);

    const auto bad = parse_duration("90q");
    PM_CHECK(!bad.ok);
    PM_CHECK(bad.error.find("ms") != std::string::npos);
}
