// Terminal output primitives (spec §6).
//
// Pure formatting: colour *detection* is a platform concern and lives in
// src/platform/console.hpp. Callers get a Style whose members are either ANSI
// escape sequences or empty strings, so no rendering code ever branches on
// "is colour enabled".

#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace postmortem::text {

struct Style {
    std::string_view heading;
    std::string_view key;
    std::string_view value;
    std::string_view dim;
    std::string_view good;
    std::string_view warn;
    std::string_view bad;
    std::string_view reset;

    [[nodiscard]] static Style plain();
    [[nodiscard]] static Style ansi();
};

// An aligned two-column table with an optional dimmed annotation per row.
// Spec §6: bit-field and state decoding is rendered as an aligned table, and
// the raw value stays visible next to the interpretation - that is what the
// annotation column is for.
class KeyValueTable {
public:
    void add(std::string key, std::string value);
    void add(std::string key, std::string value, std::string annotation);
    void add_blank();

    [[nodiscard]] bool empty() const { return rows_.empty(); }

    // `indent` is the number of leading spaces on each row.
    [[nodiscard]] std::string render(const Style& style, std::size_t indent = 2) const;

private:
    struct Row {
        std::string key;
        std::string value;
        std::string annotation;
        bool blank = false;
    };

    std::vector<Row> rows_;
};

// An aligned table with column headers.
//
// Spec §6 requires bit-field decoding to be rendered as a table of bit
// position, name, value and meaning - "not a wall of prose" - which needs more
// than the two columns KeyValueTable offers.
class Table {
public:
    explicit Table(std::vector<std::string> headers) : headers_(std::move(headers)) {}

    void add_row(std::vector<std::string> cells);

    [[nodiscard]] bool empty() const { return rows_.empty(); }
    [[nodiscard]] std::size_t row_count() const { return rows_.size(); }

    // The last column is never padded, so a long "meaning" does not drag
    // trailing spaces across the terminal.
    [[nodiscard]] std::string render(const Style& style, std::size_t indent = 2) const;

private:
    std::vector<std::string> headers_;
    std::vector<std::vector<std::string>> rows_;
};

// A section heading, e.g. "CPU", followed by a newline.
[[nodiscard]] std::string heading(std::string_view text, const Style& style);

// A wrapped paragraph, indented, for verdicts and notes.
[[nodiscard]] std::string paragraph(std::string_view text, std::size_t indent = 2,
                                    std::size_t width = 78);

// A bulleted list item, wrapped and hanging-indented under its marker.
[[nodiscard]] std::string bullet(std::string_view text, std::size_t indent = 2,
                                 std::size_t width = 78);

// Display width of a UTF-8 string, counting code points rather than bytes.
// Sufficient for the ASCII-plus-occasional-accent keys postmortem emits; it
// does not attempt East Asian wide-character handling.
[[nodiscard]] std::size_t display_width(std::string_view text);

}  // namespace postmortem::text
