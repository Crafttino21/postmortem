#include "core/render/live_view.hpp"

#include <algorithm>
#include <cmath>

#include "core/text/format.hpp"

namespace postmortem::render {
namespace {

std::string fixed(double value, int decimals = 0) {
    if (!std::isfinite(value)) return "-";
    const double scale = std::pow(10.0, decimals);
    const double rounded = std::round(value * scale) / scale;

    std::string text = std::to_string(rounded);
    const std::size_t dot = text.find('.');
    if (dot == std::string::npos) return text;
    if (decimals == 0) return text.substr(0, dot);
    return text.substr(0, std::min(text.size(), dot + 1 + static_cast<std::size_t>(decimals)));
}

std::string rate(double value) {
    if (value >= 1000000) return fixed(value / 1000000.0, 1) + "M";
    if (value >= 1000) return fixed(value / 1000.0, 1) + "k";
    return fixed(value);
}

// A proportional bar. Deliberately ASCII: the console code page is UTF-8 here,
// but block-drawing characters render inconsistently across terminals and
// fonts, and a wrong-width glyph breaks the column alignment.
std::string bar(double percent, unsigned width) {
    const double clamped = std::clamp(percent, 0.0, 100.0);
    const auto filled = static_cast<unsigned>(std::lround(clamped / 100.0 * width));
    std::string out(filled, '#');
    out.append(width - filled, '.');
    return out;
}

std::string_view load_colour(double percent, bool parked, const text::Style& style) {
    if (parked) return style.dim;
    if (percent >= 80) return style.bad;
    if (percent >= 40) return style.warn;
    if (percent >= 5) return style.value;
    return style.dim;
}

}  // namespace

std::string live_frame(const LiveSnapshot& snapshot, const text::Style& style, unsigned columns,
                       unsigned rows) {
    std::string out;
    std::vector<std::string> lines;

    const auto push = [&lines](std::string line) { lines.push_back(std::move(line)); };

    // --- header -----------------------------------------------------------
    {
        std::string header = snapshot.cpu_brand;
        if (snapshot.nominal_mhz > 0) {
            header += "   nominal " + std::to_string(snapshot.nominal_mhz) + " MHz";
        }
        if (!snapshot.uptime.empty()) header += "   up " + snapshot.uptime;
        push(std::string(style.heading) + header + std::string(style.reset));
    }
    {
        std::string status = snapshot.clock + "   " + fixed(snapshot.interval_seconds, 1) +
                             "s refresh   ";
        status += snapshot.etw_active ? "ETW: on" : "ETW: off";
        if (!snapshot.etw_active && !snapshot.etw_note.empty()) {
            status += " (" + snapshot.etw_note + ")";
        }
        if (snapshot.paused) status += "   [PAUSED]";
        push(std::string(style.dim) + status + std::string(style.reset));
    }
    push("");

    // --- per-core table ---------------------------------------------------
    const bool have_etw = snapshot.etw_active;
    // Budget the bar against the terminal width so nothing wraps: the fixed
    // columns are about 62 characters without ETW, 78 with.
    const unsigned fixed_width = have_etw ? 82u : 64u;
    const unsigned bar_width =
        columns > fixed_width + 8 ? std::min(24u, columns - fixed_width) : 8u;

    {
        std::string head = " CPU   MHz   Perf  Load ";
        head.append(bar_width > 4 ? bar_width - 4 : 0, ' ');
        head += "   C1    C2    C3   Park   IRQ/s  DPC/s";
        if (have_etw) head += "   CSw/s  eISR/s  eDPC/s";
        push(std::string(style.dim) + head + std::string(style.reset));
    }

    std::vector<LiveCore> cores = snapshot.cores;
    if (snapshot.sort_by_activity == 1) {
        std::stable_sort(cores.begin(), cores.end(), [](const LiveCore& a, const LiveCore& b) {
            return a.busy_percent > b.busy_percent;
        });
    }

    // Leave room for the header, the footer sections and the key line.
    const std::size_t reserved = 12 + snapshot.live_incidents.size() + snapshot.notes.size();
    const std::size_t room = rows > reserved ? rows - reserved : 4;
    const std::size_t shown = std::min<std::size_t>(cores.size(), room);

    for (std::size_t i = 0; i < shown; ++i) {
        const LiveCore& core = cores[i];

        std::string row = " ";
        std::string index = std::to_string(core.os_index);
        while (index.size() < 3) index.insert(index.begin(), ' ');
        row += index + "  ";

        std::string mhz = fixed(core.frequency_mhz);
        while (mhz.size() < 5) mhz.insert(mhz.begin(), ' ');
        row += mhz + "  ";

        std::string perf = fixed(core.performance_percent) + "%";
        while (perf.size() < 5) perf.insert(perf.begin(), ' ');
        row += perf + "  ";

        row.append(load_colour(core.busy_percent, core.parked, style));
        row += bar(core.busy_percent, bar_width);
        row.append(style.reset);
        row += " ";

        const auto column = [](double value) {
            std::string text = fixed(value) + "%";
            while (text.size() < 5) text.insert(text.begin(), ' ');
            return text;
        };
        row += column(core.c1_percent) + " " + column(core.c2_percent) + " " +
               column(core.c3_percent);
        row += core.parked ? std::string(style.warn) + "   yes" + std::string(style.reset)
                           : std::string("    no");
        row += "  ";

        const auto right = [](const std::string& text, std::size_t width) {
            std::string out = text;
            while (out.size() < width) out.insert(out.begin(), ' ');
            return out;
        };
        row += right(rate(core.interrupts_per_sec), 6) + " " +
               right(rate(core.dpcs_per_sec), 6);

        if (have_etw) {
            row += "  " + right(rate(core.context_switches_per_sec.value_or(0)), 6) + "  " +
                   right(rate(core.etw_interrupts_per_sec.value_or(0)), 6) + "  " +
                   right(rate(core.etw_dpcs_per_sec.value_or(0)), 6);
        }

        push(std::move(row));
    }
    if (shown < cores.size()) {
        push(std::string(style.dim) + " ... " + std::to_string(cores.size() - shown) +
             " more core(s); make the window taller" + std::string(style.reset));
    }

    // --- aggregate --------------------------------------------------------
    push("");
    {
        std::size_t deep_idle = 0;
        std::size_t parked = 0;
        for (const LiveCore& core : cores) {
            if (core.c3_percent >= 50 || core.c2_percent >= 50) ++deep_idle;
            if (core.parked) ++parked;
        }
        std::string line = " Package load " + fixed(snapshot.total_busy_percent) + "%";
        line += "    deep idle " + std::to_string(deep_idle) + "/" +
                std::to_string(cores.size());
        line += "    parked " + std::to_string(parked);
        push(std::move(line));
        push(std::string(style.dim) +
             " Deep idle is what the BIOS-level fixes in 'pm mitigate list' target." +
             std::string(style.reset));
    }

    // --- WHEA feed --------------------------------------------------------
    push("");
    push(std::string(style.heading) + "WHEA feed" + std::string(style.reset));
    if (snapshot.live_incidents.empty()) {
        push(std::string(style.dim) + " no machine check since this view started (" +
             std::to_string(snapshot.known_incidents) + " already in the log)" +
             std::string(style.reset));
    } else {
        for (const LiveIncident& incident : snapshot.live_incidents) {
            push(std::string(incident.fatal ? style.bad : style.warn) + " " + incident.when +
                 "  " + incident.text + std::string(style.reset));
        }
    }

    for (const std::string& note : snapshot.notes) {
        push(std::string(style.dim) + " " + note + std::string(style.reset));
    }

    push("");
    push(std::string(style.dim) +
         " q quit   space pause   s sort by load   r reset feed" + std::string(style.reset));

    // Clip to the window so the alternate buffer never scrolls.
    const std::size_t limit = rows > 0 ? rows - 1 : lines.size();
    for (std::size_t i = 0; i < lines.size() && i < limit; ++i) {
        out += lines[i];
        out += '\n';
    }
    return out;
}

}  // namespace postmortem::render
