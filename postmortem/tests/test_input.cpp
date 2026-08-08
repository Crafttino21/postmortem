// Parsing of values a user pastes in (spec §5's core use case).

#include <cstdint>
#include <string>
#include <vector>

#include "check.hpp"
#include "core/input/values.hpp"

using postmortem::input::parse_blob;
using postmortem::input::parse_u64;

namespace {

std::string as_text(const std::vector<std::uint8_t>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

}  // namespace

PM_TEST(input_parses_plain_hex) {
    const auto result = parse_blob("43504552");
    PM_CHECK(result.ok);
    PM_CHECK_EQ(result.format, std::string("hex"));
    PM_CHECK_EQ(as_text(result.bytes), std::string("CPER"));
}

PM_TEST(input_tolerates_how_people_actually_paste_hex) {
    // Event Viewer's Details pane wraps hex across lines with spaces.
    const auto spaced = parse_blob("43 50 45 52\n01 00 FF FF");
    PM_CHECK(spaced.ok);
    PM_CHECK_EQ(spaced.bytes.size(), std::size_t{8});
    PM_CHECK_EQ(as_text(spaced.bytes).substr(0, 4), std::string("CPER"));

    // A C array pasted out of a debugger.
    const auto c_array = parse_blob("0x43, 0x50, 0x45, 0x52");
    PM_CHECK(c_array.ok);
    PM_CHECK_EQ(as_text(c_array.bytes), std::string("CPER"));

    // Colon-separated, as some tools print it.
    const auto colons = parse_blob("43:50:45:52");
    PM_CHECK(colons.ok);
    PM_CHECK_EQ(as_text(colons.bytes), std::string("CPER"));
}

PM_TEST(input_parses_base64) {
    // "CPER" base64-encoded; contains characters no hex string can, so there
    // is nothing to disambiguate.
    const auto result = parse_blob("Q1BFUg==");
    PM_CHECK(result.ok);
    PM_CHECK_EQ(result.format, std::string("base64"));
    PM_CHECK_EQ(as_text(result.bytes), std::string("CPER"));
}

PM_TEST(input_uses_the_cper_signature_to_break_the_hex_base64_tie) {
    // "Q1BFUgEA" is valid base64 AND, once the non-hex characters are noted,
    // clearly not hex - but the interesting case is a string that could be
    // read either way. The signature settles it: whichever reading yields
    // "CPER" wins, because the alternative would decode to unrelated bytes.
    const auto ambiguous = parse_blob("Q1BFUgAB");
    PM_CHECK(ambiguous.ok);
    PM_CHECK_EQ(ambiguous.format, std::string("base64"));
    PM_CHECK_EQ(as_text(ambiguous.bytes).substr(0, 4), std::string("CPER"));

    // A plain even-length hex string with no signature stays hex, which is the
    // form spec §5 documents.
    const auto hexish = parse_blob("deadbeef");
    PM_CHECK(hexish.ok);
    PM_CHECK_EQ(hexish.format, std::string("hex"));
    PM_CHECK_EQ(hexish.bytes.size(), std::size_t{4});
    PM_CHECK_EQ(hexish.bytes[0], std::uint8_t{0xDE});
}

PM_TEST(input_rejects_unusable_blobs) {
    PM_CHECK(!parse_blob("").ok);
    PM_CHECK(!parse_blob("   \n  ").ok);

    // An odd digit count is a truncated paste, and saying so is more useful
    // than silently dropping the last nibble.
    const auto odd = parse_blob("43504");
    PM_CHECK(!odd.ok);
    PM_CHECK(odd.error.find("odd number") != std::string::npos);

    PM_CHECK(!parse_blob("this is not a blob at all!").ok);
}

PM_TEST(input_parses_register_values_in_each_base) {
    const auto hex = parse_u64("0xbea0000000000108");
    PM_CHECK(hex.ok);
    PM_CHECK_EQ(hex.value, 0xbea0000000000108ull);
    PM_CHECK_EQ(hex.base, 16);

    // Event Viewer's friendly view shows MciStat as a decimal number.
    // 13735978863480013064 == 0xBEA0000000000108, the §7 reference value.
    const auto decimal = parse_u64("13735978863480013064");
    PM_CHECK(decimal.ok);
    PM_CHECK_EQ(decimal.value, 0xBEA0000000000108ull);
    PM_CHECK_EQ(decimal.base, 10);

    const auto binary = parse_u64("0b1011");
    PM_CHECK(binary.ok);
    PM_CHECK_EQ(binary.value, std::uint64_t{11});
    PM_CHECK_EQ(binary.base, 2);

    // No prefix but containing hex letters can only be hex.
    const auto bare_hex = parse_u64("bea0000000000108");
    PM_CHECK(bare_hex.ok);
    PM_CHECK_EQ(bare_hex.value, 0xbea0000000000108ull);
    PM_CHECK_EQ(bare_hex.base, 16);
}

PM_TEST(input_register_values_tolerate_separators) {
    const auto spaced = parse_u64(" 0xBEA0 0000 0000 0108 ");
    PM_CHECK(spaced.ok);
    PM_CHECK_EQ(spaced.value, 0xBEA0000000000108ull);

    const auto ticked = parse_u64("0xBEA0'0000'0000'0108");
    PM_CHECK(ticked.ok);
    PM_CHECK_EQ(ticked.value, 0xBEA0000000000108ull);
}

PM_TEST(input_register_values_reject_overflow_rather_than_wrapping) {
    // Silently wrapping would hand the decoder a different register value and
    // produce a confident, wrong diagnosis.
    const auto too_big = parse_u64("0x1BEA0000000000108");
    PM_CHECK(!too_big.ok);
    PM_CHECK(too_big.error.find("64 bits") != std::string::npos);

    const auto decimal_overflow = parse_u64("99999999999999999999999");
    PM_CHECK(!decimal_overflow.ok);

    // The largest 64-bit value still parses.
    const auto max = parse_u64("0xFFFFFFFFFFFFFFFF");
    PM_CHECK(max.ok);
    PM_CHECK_EQ(max.value, ~0ull);
}

PM_TEST(input_register_values_reject_bad_digits) {
    const auto bad_binary = parse_u64("0b1012");
    PM_CHECK(!bad_binary.ok);
    PM_CHECK(bad_binary.error.find("base 2") != std::string::npos);

    PM_CHECK(!parse_u64("0x").ok);
    PM_CHECK(!parse_u64("").ok);
    PM_CHECK(!parse_u64("0xzz").ok);
}
