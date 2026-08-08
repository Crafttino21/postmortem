// The JSON reader, which `mitigate revert` depends on to undo a change to
// someone's machine. It is deliberately strict.

#include <string>

#include "check.hpp"
#include "core/json/reader.hpp"
#include "core/json/writer.hpp"
#include "core/text/format.hpp"

using postmortem::json::parse;
using postmortem::json::Type;

PM_TEST(json_reader_parses_a_flat_object) {
    const auto result = parse(R"({"name":"postmortem","build":26200,"ok":true,"gone":null})");
    PM_CHECK(result.ok);
    if (!result.ok) return;

    PM_CHECK_EQ(result.value.type(), Type::Object);
    PM_CHECK_EQ(result.value["name"].as_string(), std::string("postmortem"));
    PM_CHECK_EQ(result.value["build"].as_uint(), std::uint64_t{26200});
    PM_CHECK(result.value["ok"].as_bool());
    PM_CHECK(result.value["gone"].is_null());

    // An absent key yields null rather than throwing, so callers read once.
    PM_CHECK(result.value["absent"].is_null());
    PM_CHECK_EQ(result.value["absent"].as_string(), std::string());
    PM_CHECK_EQ(result.value["absent"].as_uint(7), std::uint64_t{7});
}

PM_TEST(json_reader_parses_nested_arrays_and_objects) {
    const auto result = parse(R"({"entries":[{"a":1},{"a":2}],"empty":[],"blank":{}})");
    PM_CHECK(result.ok);
    if (!result.ok) return;

    const auto& entries = result.value["entries"].as_array();
    PM_CHECK_EQ(entries.size(), std::size_t{2});
    if (entries.size() == 2) {
        PM_CHECK_EQ(entries[0]["a"].as_int(), std::int64_t{1});
        PM_CHECK_EQ(entries[1]["a"].as_int(), std::int64_t{2});
    }
    PM_CHECK(result.value["empty"].as_array().empty());
    PM_CHECK(result.value["blank"].as_object().empty());
}

PM_TEST(json_reader_handles_escapes) {
    const auto result = parse(R"({"path":"C:\\Windows","quote":"say \"hi\"","nl":"a\nb",)"
                              R"("unicode":"\u00e4"})");
    PM_CHECK(result.ok);
    if (!result.ok) return;

    PM_CHECK_EQ(result.value["path"].as_string(), std::string("C:\\Windows"));
    PM_CHECK_EQ(result.value["quote"].as_string(), std::string("say \"hi\""));
    PM_CHECK_EQ(result.value["nl"].as_string(), std::string("a\nb"));
    PM_CHECK_EQ(result.value["unicode"].as_string(), std::string("\xc3\xa4"));
}

PM_TEST(json_reader_typed_accessors_do_not_coerce) {
    const auto result = parse(R"({"number":"12","text":34})");
    PM_CHECK(result.ok);
    if (!result.ok) return;

    // A string is not silently read as a number, nor a number as a string:
    // guessing here would mean restoring the wrong value to a power setting.
    PM_CHECK_EQ(result.value["number"].as_uint(99), std::uint64_t{99});
    PM_CHECK_EQ(result.value["text"].as_string(), std::string());
}

PM_TEST(json_reader_rejects_malformed_documents) {
    PM_CHECK(!parse("").ok);
    PM_CHECK(!parse("{").ok);
    PM_CHECK(!parse("{\"a\":}").ok);
    PM_CHECK(!parse("{\"a\" 1}").ok);
    PM_CHECK(!parse("{'a':1}").ok);          // single quotes are not JSON
    PM_CHECK(!parse("[1,2,]").ok);           // trailing comma
    PM_CHECK(!parse("{\"a\":1} garbage").ok);
    PM_CHECK(!parse("{\"a\":\"unterminated}").ok);

    // Deep nesting must not exhaust the stack.
    std::string deep;
    for (int i = 0; i < 500; ++i) deep += "[";
    PM_CHECK(!parse(deep).ok);
}

PM_TEST(json_round_trips_through_the_writer) {
    // The state file is written by Writer and read back by the reader; the two
    // have to agree or `mitigate revert` silently loses the saved values.
    postmortem::json::Writer writer(true);
    writer.begin_object();
    writer.member_int("schema_version", 1);
    writer.key("entries").begin_array();
    writer.begin_object();
    writer.member("mitigation", "max-cpu-99");
    writer.member("scope", "381b4222-f694-41f0-9685-ff5bb260df2e");
    writer.member_uint("previous_ac", 100);
    writer.member_bool("previous_present", true);
    writer.member("note", "C:\\path with \"quotes\"");
    writer.end_object();
    writer.end_array();
    writer.end_object();

    const auto result = parse(writer.str());
    PM_CHECK(result.ok);
    if (!result.ok) return;

    PM_CHECK_EQ(result.value["schema_version"].as_int(), std::int64_t{1});
    const auto& entries = result.value["entries"].as_array();
    PM_CHECK_EQ(entries.size(), std::size_t{1});
    if (entries.empty()) return;

    PM_CHECK_EQ(entries[0]["mitigation"].as_string(), std::string("max-cpu-99"));
    PM_CHECK_EQ(entries[0]["previous_ac"].as_uint(), std::uint64_t{100});
    PM_CHECK(entries[0]["previous_present"].as_bool());
    PM_CHECK_EQ(entries[0]["note"].as_string(), std::string("C:\\path with \"quotes\""));
}

PM_TEST(json_reader_parses_time_and_duration_helpers) {
    // format_utc and parse_iso8601 are the pair the event model relies on.
    using postmortem::text::format_utc;
    using postmortem::text::parse_iso8601;

    const auto instant = parse_iso8601("2026-06-26T20:38:52.1234567Z");
    PM_CHECK(instant.has_value());
    if (instant.has_value()) {
        PM_CHECK_EQ(instant->seconds, std::int64_t{1782506332});
        PM_CHECK_EQ(instant->nanoseconds, 123456700u);
        PM_CHECK_EQ(format_utc(instant->seconds), std::string("2026-06-26 20:38:52Z"));
    }

    // Round trip through the epoch and a leap day.
    PM_CHECK_EQ(format_utc(0), std::string("1970-01-01 00:00:00Z"));
    const auto leap = parse_iso8601("2024-02-29T12:00:00Z");
    PM_CHECK(leap.has_value());
    if (leap.has_value()) {
        PM_CHECK_EQ(format_utc(leap->seconds), std::string("2024-02-29 12:00:00Z"));
    }

    // An offset is honoured rather than ignored.
    const auto offset = parse_iso8601("2026-06-26T22:38:52+02:00");
    PM_CHECK(offset.has_value());
    if (offset.has_value()) PM_CHECK_EQ(offset->seconds, std::int64_t{1782506332});

    PM_CHECK(!parse_iso8601("not a time").has_value());
    PM_CHECK(!parse_iso8601("2026-13-01T00:00:00Z").has_value());
}

PM_TEST(format_span_reads_naturally) {
    using postmortem::text::format_span;
    PM_CHECK_EQ(format_span(45), std::string("45s"));
    PM_CHECK_EQ(format_span(3600), std::string("1h 0m"));
    PM_CHECK_EQ(format_span(10 * 86400 + 4 * 3600 + 33 * 60), std::string("10d 4h 33m"));
}
