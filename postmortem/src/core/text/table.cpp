#include "core/text/table.hpp"

#include <algorithm>

namespace postmortem::text {

Style Style::plain() {
    return Style{};
}

Style Style::ansi() {
    Style style;
    style.heading = "\x1b[1;36m";  // bold cyan
    style.key     = "\x1b[0;37m";  // light grey
    style.value   = "\x1b[0m";
    style.dim     = "\x1b[2m";
    style.good    = "\x1b[0;32m";
    style.warn    = "\x1b[0;33m";
    style.bad     = "\x1b[1;31m";
    style.reset   = "\x1b[0m";
    return style;
}

std::size_t display_width(std::string_view text) {
    std::size_t width = 0;
    for (const char raw : text) {
        // Count lead bytes only; UTF-8 continuation bytes are 10xxxxxx.
        if ((static_cast<unsigned char>(raw) & 0xC0) != 0x80) ++width;
    }
    return width;
}

void KeyValueTable::add(std::string key, std::string value) {
    rows_.push_back(Row{std::move(key), std::move(value), {}, false});
}

void KeyValueTable::add(std::string key, std::string value, std::string annotation) {
    rows_.push_back(Row{std::move(key), std::move(value), std::move(annotation), false});
}

void KeyValueTable::add_blank() {
    rows_.push_back(Row{{}, {}, {}, true});
}

std::string KeyValueTable::render(const Style& style, std::size_t indent) const {
    std::size_t key_width = 0;
    for (const Row& row : rows_) {
        if (row.blank) continue;
        key_width = std::max(key_width, display_width(row.key));
    }

    std::string out;
    for (const Row& row : rows_) {
        if (row.blank) {
            out += '\n';
            continue;
        }

        out.append(indent, ' ');
        out.append(style.key);
        out.append(row.key);
        out.append(style.reset);
        out.append(key_width - display_width(row.key) + 2, ' ');
        out.append(style.value);
        out.append(row.value);
        out.append(style.reset);

        if (!row.annotation.empty()) {
            out += "  ";
            out.append(style.dim);
            out.append(row.annotation);
            out.append(style.reset);
        }
        out += '\n';
    }
    return out;
}

void Table::add_row(std::vector<std::string> cells) {
    rows_.push_back(std::move(cells));
}

std::string Table::render(const Style& style, std::size_t indent) const {
    const std::size_t columns = headers_.size();
    if (columns == 0) return {};

    std::vector<std::size_t> widths(columns, 0);
    for (std::size_t i = 0; i < columns; ++i) {
        widths[i] = display_width(headers_[i]);
    }
    for (const auto& row : rows_) {
        for (std::size_t i = 0; i < columns && i < row.size(); ++i) {
            widths[i] = std::max(widths[i], display_width(row[i]));
        }
    }

    const auto append_row = [&](const std::vector<std::string>& cells, std::string_view colour) {
        std::string line;
        line.append(indent, ' ');
        line.append(colour);
        for (std::size_t i = 0; i < columns; ++i) {
            const std::string_view cell = i < cells.size() ? std::string_view(cells[i])
                                                           : std::string_view{};
            line.append(cell);
            if (i + 1 < columns) {
                line.append(widths[i] - display_width(cell) + 2, ' ');
            }
        }
        line.append(style.reset);
        // Trailing spaces from a short final cell would show up when the
        // output is selected in a terminal.
        while (!line.empty() && line.back() == ' ') line.pop_back();
        line += '\n';
        return line;
    };

    std::string out = append_row(headers_, style.dim);
    for (const auto& row : rows_) out += append_row(row, style.value);
    return out;
}

namespace {

// Greedy wrap on spaces. Words longer than the width are left overlong rather
// than broken - a GUID or a hex value must stay copy-pasteable.
std::string wrap(std::string_view text, std::size_t first_indent, std::size_t hanging_indent,
                 std::size_t width) {
    std::string out;
    std::size_t column = 0;
    bool first_word = true;
    bool first_line = true;

    std::size_t pos = 0;
    while (pos < text.size()) {
        while (pos < text.size() && text[pos] == ' ') ++pos;
        const std::size_t start = pos;
        while (pos < text.size() && text[pos] != ' ') ++pos;
        if (pos == start) break;
        const std::string_view word = text.substr(start, pos - start);

        const std::size_t indent = first_line ? first_indent : hanging_indent;
        if (first_word) {
            out.append(indent, ' ');
            column = indent;
        } else if (column + 1 + word.size() > width) {
            out += '\n';
            out.append(hanging_indent, ' ');
            column = hanging_indent;
            first_line = false;
        } else {
            out += ' ';
            ++column;
        }

        out.append(word);
        column += word.size();
        first_word = false;
    }

    if (!out.empty()) out += '\n';
    return out;
}

}  // namespace

std::string paragraph(std::string_view text, std::size_t indent, std::size_t width) {
    return wrap(text, indent, indent, width);
}

std::string bullet(std::string_view text, std::size_t indent, std::size_t width) {
    std::string body = wrap(text, indent + 2, indent + 2, width);
    if (body.size() > indent + 2) {
        // Replace the two leading spaces of the first line with the marker.
        body[indent] = '-';
    }
    return body;
}

std::string heading(std::string_view text, const Style& style) {
    std::string out;
    out.append(style.heading);
    out.append(text);
    out.append(style.reset);
    out += '\n';
    return out;
}

}  // namespace postmortem::text
