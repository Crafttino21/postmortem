#include "core/json/reader.hpp"

#include <cmath>
#include <cstdlib>

namespace postmortem::json {
namespace {

const std::string& empty_string() {
    static const std::string value;
    return value;
}

const Array& empty_array() {
    static const Array value;
    return value;
}

const Object& empty_object() {
    static const Object value;
    return value;
}

const Value& null_value() {
    static const Value value;
    return value;
}

class Parser {
public:
    explicit Parser(std::string_view text) : text_(text) {}

    ParseResult run() {
        ParseResult result;
        skip_space();

        Value value;
        if (!parse_value(value, 0)) {
            result.error = error_.empty() ? "malformed JSON" : error_;
            return result;
        }

        skip_space();
        if (pos_ != text_.size()) {
            result.error = "trailing content after the top-level value, at offset " +
                           std::to_string(pos_);
            return result;
        }

        result.ok = true;
        result.value = std::move(value);
        return result;
    }

private:
    static constexpr int kMaxDepth = 64;

    bool fail(std::string message) {
        if (error_.empty()) error_ = std::move(message) + " at offset " + std::to_string(pos_);
        return false;
    }

    void skip_space() {
        while (pos_ < text_.size() &&
               (text_[pos_] == ' ' || text_[pos_] == '\t' || text_[pos_] == '\n' ||
                text_[pos_] == '\r')) {
            ++pos_;
        }
    }

    bool literal(std::string_view word) {
        if (text_.compare(pos_, word.size(), word) != 0) return false;
        pos_ += word.size();
        return true;
    }

    bool parse_value(Value& out, int depth) {
        if (depth > kMaxDepth) return fail("nesting is too deep");
        skip_space();
        if (pos_ >= text_.size()) return fail("unexpected end of input");

        switch (text_[pos_]) {
            case '{': return parse_object(out, depth);
            case '[': return parse_array(out, depth);
            case '"': {
                std::string text;
                if (!parse_string(text)) return false;
                out = Value::make_string(std::move(text));
                return true;
            }
            case 't':
                if (!literal("true")) return fail("expected 'true'");
                out = Value::make_bool(true);
                return true;
            case 'f':
                if (!literal("false")) return fail("expected 'false'");
                out = Value::make_bool(false);
                return true;
            case 'n':
                if (!literal("null")) return fail("expected 'null'");
                out = Value::make_null();
                return true;
            default:
                return parse_number(out);
        }
    }

    bool parse_object(Value& out, int depth) {
        ++pos_;   // '{'
        Object object;
        skip_space();
        if (pos_ < text_.size() && text_[pos_] == '}') {
            ++pos_;
            out = Value::make_object(std::move(object));
            return true;
        }

        for (;;) {
            skip_space();
            if (pos_ >= text_.size() || text_[pos_] != '"') return fail("expected a key");
            std::string key;
            if (!parse_string(key)) return false;

            skip_space();
            if (pos_ >= text_.size() || text_[pos_] != ':') return fail("expected ':'");
            ++pos_;

            Value value;
            if (!parse_value(value, depth + 1)) return false;
            object.insert_or_assign(std::move(key), std::move(value));

            skip_space();
            if (pos_ >= text_.size()) return fail("unterminated object");
            if (text_[pos_] == ',') {
                ++pos_;
                continue;
            }
            if (text_[pos_] == '}') {
                ++pos_;
                out = Value::make_object(std::move(object));
                return true;
            }
            return fail("expected ',' or '}'");
        }
    }

    bool parse_array(Value& out, int depth) {
        ++pos_;   // '['
        Array array;
        skip_space();
        if (pos_ < text_.size() && text_[pos_] == ']') {
            ++pos_;
            out = Value::make_array(std::move(array));
            return true;
        }

        for (;;) {
            Value value;
            if (!parse_value(value, depth + 1)) return false;
            array.push_back(std::move(value));

            skip_space();
            if (pos_ >= text_.size()) return fail("unterminated array");
            if (text_[pos_] == ',') {
                ++pos_;
                continue;
            }
            if (text_[pos_] == ']') {
                ++pos_;
                out = Value::make_array(std::move(array));
                return true;
            }
            return fail("expected ',' or ']'");
        }
    }

    bool parse_string(std::string& out) {
        ++pos_;   // opening quote
        out.clear();

        while (pos_ < text_.size()) {
            const char c = text_[pos_];
            if (c == '"') {
                ++pos_;
                return true;
            }
            if (c != '\\') {
                out += c;
                ++pos_;
                continue;
            }

            ++pos_;
            if (pos_ >= text_.size()) return fail("unterminated escape");
            switch (text_[pos_]) {
                case '"':  out += '"';  break;
                case '\\': out += '\\'; break;
                case '/':  out += '/';  break;
                case 'b':  out += '\b'; break;
                case 'f':  out += '\f'; break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                case 'u': {
                    if (pos_ + 4 >= text_.size()) return fail("truncated \\u escape");
                    unsigned code = 0;
                    for (int i = 1; i <= 4; ++i) {
                        const char digit = text_[pos_ + i];
                        int value = -1;
                        if (digit >= '0' && digit <= '9') value = digit - '0';
                        else if (digit >= 'a' && digit <= 'f') value = digit - 'a' + 10;
                        else if (digit >= 'A' && digit <= 'F') value = digit - 'A' + 10;
                        if (value < 0) return fail("bad hex digit in \\u escape");
                        code = code * 16 + static_cast<unsigned>(value);
                    }
                    pos_ += 4;
                    // Encode as UTF-8. Surrogate pairs are not recombined:
                    // nothing this tool writes produces them.
                    if (code < 0x80) {
                        out += static_cast<char>(code);
                    } else if (code < 0x800) {
                        out += static_cast<char>(0xC0 | (code >> 6));
                        out += static_cast<char>(0x80 | (code & 0x3F));
                    } else {
                        out += static_cast<char>(0xE0 | (code >> 12));
                        out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
                        out += static_cast<char>(0x80 | (code & 0x3F));
                    }
                    break;
                }
                default:
                    return fail("unknown escape");
            }
            ++pos_;
        }
        return fail("unterminated string");
    }

    bool parse_number(Value& out) {
        const std::size_t start = pos_;
        if (pos_ < text_.size() && (text_[pos_] == '-' || text_[pos_] == '+')) ++pos_;
        bool any_digit = false;
        while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
            ++pos_;
            any_digit = true;
        }
        if (pos_ < text_.size() && text_[pos_] == '.') {
            ++pos_;
            while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
                ++pos_;
                any_digit = true;
            }
        }
        if (!any_digit) return fail("expected a value");

        if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < text_.size() && (text_[pos_] == '-' || text_[pos_] == '+')) ++pos_;
            bool exponent_digit = false;
            while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
                ++pos_;
                exponent_digit = true;
            }
            if (!exponent_digit) return fail("exponent has no digits");
        }

        const std::string number(text_.substr(start, pos_ - start));
        out = Value::make_number(std::strtod(number.c_str(), nullptr));
        return true;
    }

    std::string_view text_;
    std::size_t pos_ = 0;
    std::string error_;
};

}  // namespace

Value::Value() = default;
Value::~Value() = default;

Value::Value(const Value& other)
    : type_(other.type_), bool_(other.bool_), number_(other.number_), string_(other.string_) {
    if (other.array_) array_ = std::make_unique<Array>(*other.array_);
    if (other.object_) object_ = std::make_unique<Object>(*other.object_);
}

Value& Value::operator=(const Value& other) {
    if (this == &other) return *this;
    type_ = other.type_;
    bool_ = other.bool_;
    number_ = other.number_;
    string_ = other.string_;
    array_ = other.array_ ? std::make_unique<Array>(*other.array_) : nullptr;
    object_ = other.object_ ? std::make_unique<Object>(*other.object_) : nullptr;
    return *this;
}

Value::Value(Value&& other) noexcept = default;
Value& Value::operator=(Value&& other) noexcept = default;

Value Value::make_null() {
    return Value{};
}

Value Value::make_bool(bool value) {
    Value result;
    result.type_ = Type::Bool;
    result.bool_ = value;
    return result;
}

Value Value::make_number(double value) {
    Value result;
    result.type_ = Type::Number;
    result.number_ = value;
    return result;
}

Value Value::make_string(std::string value) {
    Value result;
    result.type_ = Type::String;
    result.string_ = std::move(value);
    return result;
}

Value Value::make_array(Array value) {
    Value result;
    result.type_ = Type::Array;
    result.array_ = std::make_unique<Array>(std::move(value));
    return result;
}

Value Value::make_object(Object value) {
    Value result;
    result.type_ = Type::Object;
    result.object_ = std::make_unique<Object>(std::move(value));
    return result;
}

bool Value::as_bool(bool fallback) const {
    return type_ == Type::Bool ? bool_ : fallback;
}

double Value::as_double(double fallback) const {
    return type_ == Type::Number ? number_ : fallback;
}

std::int64_t Value::as_int(std::int64_t fallback) const {
    if (type_ != Type::Number) return fallback;
    return static_cast<std::int64_t>(std::llround(number_));
}

std::uint64_t Value::as_uint(std::uint64_t fallback) const {
    if (type_ != Type::Number || number_ < 0) return fallback;
    return static_cast<std::uint64_t>(std::llround(number_));
}

const std::string& Value::as_string() const {
    return type_ == Type::String ? string_ : empty_string();
}

const Array& Value::as_array() const {
    return (type_ == Type::Array && array_) ? *array_ : empty_array();
}

const Object& Value::as_object() const {
    return (type_ == Type::Object && object_) ? *object_ : empty_object();
}

const Value& Value::operator[](std::string_view key) const {
    if (type_ != Type::Object || !object_) return null_value();
    const auto found = object_->find(std::string(key));
    return found == object_->end() ? null_value() : found->second;
}

bool Value::has(std::string_view key) const {
    if (type_ != Type::Object || !object_) return false;
    return object_->find(std::string(key)) != object_->end();
}

ParseResult parse(std::string_view text) {
    Parser parser(text);
    return parser.run();
}

}  // namespace postmortem::json
