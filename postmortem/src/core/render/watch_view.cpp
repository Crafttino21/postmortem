#include "core/render/watch_view.hpp"

#include <algorithm>
#include <cmath>

#include "core/text/format.hpp"

namespace postmortem::render {
namespace {

using text::to_hex;

std::string percent(double value) {
    return std::to_string(static_cast<int>(std::lround(value))) + "%";
}

std::string right(const std::string& text, std::size_t width) {
    std::string out = text;
    while (out.size() < width) out.insert(out.begin(), ' ');
    return out;
}

}  // namespace

std::string stack_frame(const StackSnapshot& snapshot, const text::Style& style,
                        unsigned columns, unsigned rows) {
    std::vector<std::string> lines;
    const auto push = [&lines](std::string line) { lines.push_back(std::move(line)); };

    {
        std::string header = "Hottest stacks   " + std::to_string(snapshot.total_samples) +
                             " samples this interval";
        if (snapshot.total_samples > 0) {
            header += "   kernel " +
                      percent(static_cast<double>(snapshot.kernel_samples) * 100.0 /
                              static_cast<double>(snapshot.total_samples)) +
                      "  user " +
                      percent(static_cast<double>(snapshot.user_samples) * 100.0 /
                              static_cast<double>(snapshot.total_samples));
        }
        push(std::string(style.heading) + header + std::string(style.reset));
    }

    if (snapshot.total_samples == 0) {
        push("");
        push(std::string(style.dim) +
             "  no samples yet - the profiling interrupt has not fired since the last frame" +
             std::string(style.reset));
    }
    push("");

    // Reserve room for the header, the notes and the key line.
    const std::size_t reserved = 6 + snapshot.notes.size();
    std::size_t budget = rows > reserved ? rows - reserved : 6;

    for (const HotStack& stack : snapshot.stacks) {
        const std::size_t needed = 1 + std::min<std::size_t>(stack.frames.size(), snapshot.depth);
        if (budget < needed + 1) break;
        budget -= needed;

        std::string head = "  " + right(std::to_string(stack.count), 6) + "  " +
                           right(percent(stack.share_percent), 4) + "  ";
        if (!stack.process_name.empty()) {
            head += stack.process_name + " (" + std::to_string(stack.process_id) + ")";
        } else {
            head += "pid " + std::to_string(stack.process_id);
        }
        push(std::string(style.value) + head + std::string(style.reset));

        for (std::size_t i = 0; i < stack.frames.size() && i < snapshot.depth; ++i) {
            const StackFrameLine& frame = stack.frames[i];
            std::string line = "                  ";
            // Innermost frame first; deeper frames indented so the direction
            // of the call chain is readable at a glance.
            line.append(i * 2, ' ');
            line += frame.text;
            if (line.size() > columns && columns > 4) line.resize(columns);
            push(std::string(frame.kernel ? style.warn : style.dim) + line +
                 std::string(style.reset));
        }
    }

    if (snapshot.dropped > 0) {
        push("");
        push(std::string(style.warn) + "  " + std::to_string(snapshot.dropped) +
             " sample(s) dropped: more distinct stacks than the buffer holds" +
             std::string(style.reset));
    }
    if (!snapshot.symbols_available && snapshot.total_samples > 0) {
        push(std::string(style.dim) +
             "  no function names resolved - frames show module+offset. Symbols are only "
             "looked up locally; no symbol server is contacted." +
             std::string(style.reset));
    }
    for (const std::string& note : snapshot.notes) {
        push(std::string(style.dim) + "  " + note + std::string(style.reset));
    }

    std::string out;
    const std::size_t limit = rows > 0 ? rows - 1 : lines.size();
    for (std::size_t i = 0; i < lines.size() && i < limit; ++i) {
        out += lines[i];
        out += '\n';
    }
    return out;
}

std::string memory_frame(const MemoryWatch& watch, const text::Style& style, unsigned columns,
                         unsigned rows) {
    constexpr std::size_t kPerLine = 16;

    std::vector<std::string> lines;
    const auto push = [&lines](std::string line) { lines.push_back(std::move(line)); };

    {
        std::string header = watch.process_name.empty()
                                 ? "pid " + std::to_string(watch.process_id)
                                 : watch.process_name + " (" +
                                       std::to_string(watch.process_id) + ")";
        header += "   " + to_hex(watch.address, 16);
        if (!watch.address_label.empty()) header += "  " + watch.address_label;
        header += "   " + std::to_string(watch.bytes.size()) + " bytes";
        push(std::string(style.heading) + header + std::string(style.reset));
    }
    {
        std::string status = watch.clock + "   tick " + std::to_string(watch.ticks);
        if (watch.readable < watch.bytes.size()) {
            status += "   only " + std::to_string(watch.readable) + " byte(s) readable";
        }
        if (watch.paused) status += "   [PAUSED]";
        push(std::string(style.dim) + status + std::string(style.reset));
    }
    push("");

    if (!watch.error.empty()) {
        push(std::string(style.bad) + "  " + watch.error + std::string(style.reset));
        std::string out;
        for (const std::string& line : lines) out += line + "\n";
        return out;
    }

    std::size_t changed_this_tick = 0;
    std::size_t ever_changed = 0;
    for (std::size_t i = 0; i < watch.bytes.size(); ++i) {
        if (i < watch.changed_now.size() && watch.changed_now[i]) ++changed_this_tick;
        if (i < watch.change_counts.size() && watch.change_counts[i] > 0) ++ever_changed;
    }

    push(std::string(style.dim) + "  Offset    Bytes" + std::string(style.reset));

    // Keep a few lines for the footer.
    const std::size_t reserved = 8;
    const std::size_t room = rows > reserved ? (rows - reserved) : 4;
    const std::size_t max_lines = std::min(room, (watch.bytes.size() + kPerLine - 1) / kPerLine);

    for (std::size_t line = 0; line < max_lines; ++line) {
        const std::size_t base = line * kPerLine;
        const std::size_t count = std::min(kPerLine, watch.bytes.size() - base);

        std::string row = "  ";
        const std::string offset = to_hex(watch.address + base, 8);
        row.append(offset.begin() + 2, offset.end());
        row += "  ";

        std::string ascii;
        for (std::size_t i = 0; i < kPerLine; ++i) {
            const std::size_t index = base + i;
            if (i < count) {
                const bool readable = index < watch.readable;
                const bool changed =
                    index < watch.changed_now.size() && watch.changed_now[index];
                const bool ever =
                    index < watch.change_counts.size() && watch.change_counts[index] > 0;

                if (!readable) {
                    row.append(style.dim);
                    row += "??";
                    row.append(style.reset);
                    ascii += '?';
                } else {
                    // Changed this tick is loud; changed at some point is
                    // marked more quietly, so a volatile field stays visible
                    // between the ticks it happens to move on.
                    if (changed) {
                        row.append(style.bad);
                    } else if (ever) {
                        row.append(style.warn);
                    }
                    static constexpr char kDigits[] = "0123456789ABCDEF";
                    const std::uint8_t byte = watch.bytes[index];
                    row += kDigits[(byte >> 4) & 0xF];
                    row += kDigits[byte & 0xF];
                    if (changed || ever) row.append(style.reset);
                    ascii += (byte >= 0x20 && byte < 0x7F) ? static_cast<char>(byte) : '.';
                }
            } else {
                row += "  ";
                ascii += ' ';
            }
            row += ' ';
            if (i == 7) row += ' ';
        }

        if (columns >= 80) {
            row += ' ';
            row += ascii;
        }
        push(std::move(row));
    }

    if (max_lines * kPerLine < watch.bytes.size()) {
        push(std::string(style.dim) + "  ... " +
             std::to_string(watch.bytes.size() - max_lines * kPerLine) +
             " more byte(s); make the window taller or lower --len" +
             std::string(style.reset));
    }

    push("");
    push("  " + std::to_string(changed_this_tick) + " byte(s) changed this tick, " +
         std::to_string(ever_changed) + " of " + std::to_string(watch.bytes.size()) +
         " have ever changed");
    push(std::string(style.dim) +
         "  red = changed this tick, yellow = changed earlier, ?? = not readable" +
         std::string(style.reset));
    push("");
    push(std::string(style.dim) + "  q quit   space pause   r reset change history" +
         std::string(style.reset));

    std::string out;
    const std::size_t limit = rows > 0 ? rows - 1 : lines.size();
    for (std::size_t i = 0; i < lines.size() && i < limit; ++i) {
        out += lines[i];
        out += '\n';
    }
    return out;
}

}  // namespace postmortem::render
