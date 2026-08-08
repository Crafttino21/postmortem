// A small hand-rolled JSON writer.
//
// Spec §3 asks for either a vendored single-header library or a hand-rolled
// serializer, with the choice justified. postmortem only ever *writes* JSON -
// nothing in the design consumes it - and the documents it writes are flat
// records of strings, integers and booleans. A dependency-free ~150-line
// streaming writer covers that completely, keeps the static-CRT binary small,
// and avoids pulling a 25k-line header into every translation unit. If a
// future milestone needs to *parse* JSON (reading back the mitigation state
// snapshot in §4.9 is the only candidate), revisit this decision then.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace postmortem::json {

// Escapes a string for inclusion in a JSON document. Bytes >= 0x80 are passed
// through unchanged: input is expected to already be UTF-8.
[[nodiscard]] std::string escape(std::string_view text);

class Writer {
public:
    explicit Writer(bool pretty = true);

    Writer& begin_object();
    Writer& end_object();
    Writer& begin_array();
    Writer& end_array();

    // Object member key. Must be followed by exactly one value.
    Writer& key(std::string_view name);

    // Standalone values (array elements, or the value after key()).
    Writer& value(std::string_view text);
    Writer& value_int(std::int64_t number);
    Writer& value_uint(std::uint64_t number);
    Writer& value_bool(bool flag);
    Writer& value_null();

    // key() + value() in one call.
    Writer& member(std::string_view name, std::string_view text);
    Writer& member_int(std::string_view name, std::int64_t number);
    Writer& member_uint(std::string_view name, std::uint64_t number);
    Writer& member_bool(std::string_view name, bool flag);
    Writer& member_null(std::string_view name);

    // Convenience for the many places the spec wants the raw value alongside
    // the interpretation: writes "0x..." as a string.
    Writer& member_hex(std::string_view name, std::uint64_t value, int digits = 0);

    [[nodiscard]] const std::string& str() const { return out_; }

    [[nodiscard]] std::string take() { return std::move(out_); }

private:
    struct Frame {
        bool is_array;
        int count;
    };

    void begin_value();
    void indent(std::size_t depth);

    std::string out_;
    std::vector<Frame> stack_;
    bool pretty_;
    bool pending_key_ = false;
};

}  // namespace postmortem::json
