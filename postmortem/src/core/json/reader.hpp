// A small JSON reader.
//
// writer.hpp justified hand-rolling the serializer on the grounds that nothing
// consumed JSON. Milestone 8 changes that: `mitigate revert` has to read back
// the snapshot written by `apply`, and spec §4.9 requires the revert to restore
// "from that snapshot, not from a hardcoded default" - so the file must
// actually be parsed. This stays hand-rolled for the same reasons as the
// writer: the documents are ours, flat, and small, and a dependency-free
// static binary is worth more here than generality.
//
// It is strict on purpose. state.json is the record of how to undo a change to
// someone's machine; a reader that guesses at malformed input is worse than one
// that refuses.

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace postmortem::json {

class Value;
using Object = std::map<std::string, Value>;
using Array = std::vector<Value>;

enum class Type {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
};

class Value {
public:
    Value();
    ~Value();
    Value(const Value& other);
    Value& operator=(const Value& other);
    Value(Value&& other) noexcept;
    Value& operator=(Value&& other) noexcept;

    static Value make_null();
    static Value make_bool(bool value);
    static Value make_number(double value);
    static Value make_string(std::string value);
    static Value make_array(Array value);
    static Value make_object(Object value);

    [[nodiscard]] Type type() const { return type_; }
    [[nodiscard]] bool is_null() const { return type_ == Type::Null; }

    // Typed accessors. Each returns the fallback when the value is absent or
    // of the wrong type, so callers never have to check twice.
    [[nodiscard]] bool as_bool(bool fallback = false) const;
    [[nodiscard]] double as_double(double fallback = 0.0) const;
    [[nodiscard]] std::int64_t as_int(std::int64_t fallback = 0) const;
    [[nodiscard]] std::uint64_t as_uint(std::uint64_t fallback = 0) const;
    [[nodiscard]] const std::string& as_string() const;
    [[nodiscard]] const Array& as_array() const;
    [[nodiscard]] const Object& as_object() const;

    // Object member lookup; returns a null Value when absent.
    [[nodiscard]] const Value& operator[](std::string_view key) const;
    [[nodiscard]] bool has(std::string_view key) const;

private:
    Type type_ = Type::Null;
    bool bool_ = false;
    double number_ = 0.0;
    std::string string_;
    std::unique_ptr<Array> array_;
    std::unique_ptr<Object> object_;
};

struct ParseResult {
    bool ok = false;
    Value value;
    std::string error;
};

[[nodiscard]] ParseResult parse(std::string_view text);

}  // namespace postmortem::json
