#include "core/json/writer.hpp"

#include <array>

#include "core/text/format.hpp"

namespace postmortem::json {
namespace {

constexpr std::array<char, 16> kHexDigits{
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

void append_u4(std::string& out, unsigned value) {
    out += kHexDigits[(value >> 12) & 0xF];
    out += kHexDigits[(value >> 8) & 0xF];
    out += kHexDigits[(value >> 4) & 0xF];
    out += kHexDigits[value & 0xF];
}

}  // namespace

std::string escape(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 2);
    for (const char raw : text) {
        const auto byte = static_cast<unsigned char>(raw);
        switch (byte) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (byte < 0x20) {
                    // Control characters must be escaped; everything else,
                    // including UTF-8 continuation bytes, passes through.
                    out += "\\u";
                    append_u4(out, byte);
                } else {
                    out += raw;
                }
                break;
        }
    }
    return out;
}

Writer::Writer(bool pretty) : pretty_(pretty) {}

void Writer::indent(std::size_t depth) {
    if (!pretty_) return;
    out_.append(depth * 2, ' ');
}

void Writer::begin_value() {
    if (pending_key_) {
        pending_key_ = false;
        return;
    }
    if (stack_.empty()) return;  // top-level value

    Frame& frame = stack_.back();
    if (frame.count > 0) out_ += ',';
    if (pretty_) {
        out_ += '\n';
        indent(stack_.size());
    }
    ++frame.count;
}

Writer& Writer::begin_object() {
    begin_value();
    out_ += '{';
    stack_.push_back({false, 0});
    return *this;
}

Writer& Writer::end_object() {
    const Frame frame = stack_.back();
    stack_.pop_back();
    if (pretty_ && frame.count > 0) {
        out_ += '\n';
        indent(stack_.size());
    }
    out_ += '}';
    return *this;
}

Writer& Writer::begin_array() {
    begin_value();
    out_ += '[';
    stack_.push_back({true, 0});
    return *this;
}

Writer& Writer::end_array() {
    const Frame frame = stack_.back();
    stack_.pop_back();
    if (pretty_ && frame.count > 0) {
        out_ += '\n';
        indent(stack_.size());
    }
    out_ += ']';
    return *this;
}

Writer& Writer::key(std::string_view name) {
    Frame& frame = stack_.back();
    if (frame.count > 0) out_ += ',';
    if (pretty_) {
        out_ += '\n';
        indent(stack_.size());
    }
    ++frame.count;

    out_ += '"';
    out_ += escape(name);
    out_ += '"';
    out_ += ':';
    if (pretty_) out_ += ' ';
    pending_key_ = true;
    return *this;
}

Writer& Writer::value(std::string_view text) {
    begin_value();
    out_ += '"';
    out_ += escape(text);
    out_ += '"';
    return *this;
}

Writer& Writer::value_int(std::int64_t number) {
    begin_value();
    out_ += std::to_string(number);
    return *this;
}

Writer& Writer::value_uint(std::uint64_t number) {
    begin_value();
    out_ += std::to_string(number);
    return *this;
}

Writer& Writer::value_bool(bool flag) {
    begin_value();
    out_ += flag ? "true" : "false";
    return *this;
}

Writer& Writer::value_null() {
    begin_value();
    out_ += "null";
    return *this;
}

Writer& Writer::member(std::string_view name, std::string_view text) {
    return key(name).value(text);
}

Writer& Writer::member_int(std::string_view name, std::int64_t number) {
    return key(name).value_int(number);
}

Writer& Writer::member_uint(std::string_view name, std::uint64_t number) {
    return key(name).value_uint(number);
}

Writer& Writer::member_bool(std::string_view name, bool flag) {
    return key(name).value_bool(flag);
}

Writer& Writer::member_null(std::string_view name) {
    return key(name).value_null();
}

Writer& Writer::member_hex(std::string_view name, std::uint64_t value_in, int digits) {
    return key(name).value(text::to_hex(value_in, digits));
}

}  // namespace postmortem::json
