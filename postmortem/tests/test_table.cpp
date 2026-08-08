#include <string>

#include "check.hpp"
#include "core/text/table.hpp"

using postmortem::text::KeyValueTable;
using postmortem::text::Style;

PM_TEST(table_aligns_the_value_column) {
    KeyValueTable table;
    table.add("Brand", "AMD Ryzen 9 5950X");
    table.add("Vendor", "AuthenticAMD");
    table.add("Cores / Threads", "16 / 32");

    // Values start two columns past the widest key ("Cores / Threads", 15).
    const std::string expected =
        "  Brand            AMD Ryzen 9 5950X\n"
        "  Vendor           AuthenticAMD\n"
        "  Cores / Threads  16 / 32\n";
    PM_CHECK_EQ(table.render(Style::plain()), expected);
}

PM_TEST(table_renders_annotations_and_blank_rows) {
    KeyValueTable table;
    table.add("MciStat", "uncorrected", "raw 0xBEA0000000000108");
    table.add_blank();
    table.add("Bank", "5");

    const std::string expected =
        "  MciStat  uncorrected  raw 0xBEA0000000000108\n"
        "\n"
        "  Bank     5\n";
    PM_CHECK_EQ(table.render(Style::plain()), expected);
}

PM_TEST(table_indent_is_configurable) {
    KeyValueTable table;
    table.add("Key", "value");
    PM_CHECK_EQ(table.render(Style::plain(), 0), std::string("Key  value\n"));
    PM_CHECK_EQ(table.render(Style::plain(), 4), std::string("    Key  value\n"));
}

PM_TEST(table_alignment_counts_code_points_not_bytes) {
    // A multi-byte key must not push its own value column out of line - which
    // is what byte-length padding would do.
    // "Größe" spelled byte-by-byte: 5 code points in 7 bytes. The literals are
    // split so that the hex escape does not swallow the following character.
    KeyValueTable table;
    table.add("Gr\xc3\xb6\xc3\x9f" "e", "8");
    table.add("Value", "9");

    const std::string expected =
        "  Gr\xc3\xb6\xc3\x9f" "e  8\n"
        "  Value  9\n";
    PM_CHECK_EQ(table.render(Style::plain()), expected);
    PM_CHECK_EQ(postmortem::text::display_width("Gr\xc3\xb6\xc3\x9f" "e"), std::size_t{5});
}

PM_TEST(table_plain_style_emits_no_escape_sequences) {
    KeyValueTable table;
    table.add("Key", "value", "note");
    const std::string plain = table.render(Style::plain());
    PM_CHECK(plain.find('\x1b') == std::string::npos);

    const std::string coloured = table.render(Style::ansi());
    PM_CHECK(coloured.find('\x1b') != std::string::npos);
}

PM_TEST(table_heading_uses_the_style) {
    PM_CHECK_EQ(postmortem::text::heading("CPU", Style::plain()), std::string("CPU\n"));
    PM_CHECK(postmortem::text::heading("CPU", Style::ansi()).find("CPU") != std::string::npos);
}
