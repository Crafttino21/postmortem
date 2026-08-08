#include <string>

#include "check.hpp"
#include "core/json/writer.hpp"
#include "core/text/format.hpp"

using postmortem::json::Writer;

PM_TEST(json_escapes_the_characters_that_matter) {
    PM_CHECK_EQ(postmortem::json::escape("plain"), std::string("plain"));
    PM_CHECK_EQ(postmortem::json::escape("say \"hi\""), std::string("say \\\"hi\\\""));
    PM_CHECK_EQ(postmortem::json::escape("C:\\Windows"), std::string("C:\\\\Windows"));
    PM_CHECK_EQ(postmortem::json::escape("a\nb\tc"), std::string("a\\nb\\tc"));

    // Control characters become \u00XX; UTF-8 passes through untouched, which
    // matters for firmware strings with accented vendor names.
    PM_CHECK_EQ(postmortem::json::escape(std::string(1, '\x01')), std::string("\\u0001"));
    // "Größe" spelled byte-by-byte; the literals are split so that the hex
    // escape does not swallow the following character.
    PM_CHECK_EQ(postmortem::json::escape("Gr\xc3\xb6\xc3\x9f" "e"),
                std::string("Gr\xc3\xb6\xc3\x9f" "e"));
}

PM_TEST(json_writes_compact_documents) {
    Writer writer(false);
    writer.begin_object();
    writer.member("name", "postmortem");
    writer.member_uint("build", 26200u);
    writer.member_bool("elevated", false);
    writer.member_null("dump");
    writer.end_object();

    PM_CHECK_EQ(writer.str(),
                std::string(R"({"name":"postmortem","build":26200,"elevated":false,"dump":null})"));
}

PM_TEST(json_writes_pretty_documents) {
    Writer writer(true);
    writer.begin_object();
    writer.key("cpu").begin_object();
    writer.member("vendor", "AuthenticAMD");
    writer.member_hex("cpuid_1_eax", 0x00A20F12ull, 8);
    writer.end_object();
    writer.key("banks").begin_array();
    writer.value_uint(5);
    writer.value_uint(6);
    writer.end_array();
    writer.end_object();

    const std::string expected =
        "{\n"
        "  \"cpu\": {\n"
        "    \"vendor\": \"AuthenticAMD\",\n"
        "    \"cpuid_1_eax\": \"0x00A20F12\"\n"
        "  },\n"
        "  \"banks\": [\n"
        "    5,\n"
        "    6\n"
        "  ]\n"
        "}";
    PM_CHECK_EQ(writer.str(), expected);
}

PM_TEST(json_writes_empty_containers_on_one_line) {
    Writer writer(true);
    writer.begin_object();
    writer.key("sections").begin_array();
    writer.end_array();
    writer.key("meta").begin_object();
    writer.end_object();
    writer.end_object();

    PM_CHECK_EQ(writer.str(), std::string("{\n  \"sections\": [],\n  \"meta\": {}\n}"));
}

PM_TEST(json_negative_integers_round_trip) {
    Writer writer(false);
    writer.begin_object();
    writer.member_int("offset", -1);
    writer.end_object();
    PM_CHECK_EQ(writer.str(), std::string(R"({"offset":-1})"));
}

PM_TEST(format_to_hex_pads_and_uppercases) {
    using postmortem::text::to_hex;
    PM_CHECK_EQ(to_hex(0), std::string("0x0"));
    PM_CHECK_EQ(to_hex(0, 8), std::string("0x00000000"));
    PM_CHECK_EQ(to_hex(0xBEA0000000000108ull, 16), std::string("0xBEA0000000000108"));
    PM_CHECK_EQ(to_hex(0x19u, 2), std::string("0x19"));
    // A value wider than the requested padding is never truncated.
    PM_CHECK_EQ(to_hex(0x1234u, 2), std::string("0x1234"));
}
