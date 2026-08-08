#include "core/xml/parse.hpp"

#include <cctype>

namespace postmortem::xml {
namespace {

bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

bool is_name_start(char c) {
    return std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_' || c == ':';
}

bool is_name_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' || c == ':' ||
           c == '-' || c == '.';
}

// Appends a code point as UTF-8. Only needed for numeric character references.
void append_utf8(std::string& out, unsigned code_point) {
    if (code_point < 0x80) {
        out += static_cast<char>(code_point);
    } else if (code_point < 0x800) {
        out += static_cast<char>(0xC0 | (code_point >> 6));
        out += static_cast<char>(0x80 | (code_point & 0x3F));
    } else if (code_point < 0x10000) {
        out += static_cast<char>(0xE0 | (code_point >> 12));
        out += static_cast<char>(0x80 | ((code_point >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (code_point & 0x3F));
    } else if (code_point <= 0x10FFFF) {
        out += static_cast<char>(0xF0 | (code_point >> 18));
        out += static_cast<char>(0x80 | ((code_point >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((code_point >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (code_point & 0x3F));
    }
}

std::string_view strip_prefix(std::string_view name) {
    const std::size_t colon = name.rfind(':');
    if (colon == std::string_view::npos) return name;
    return name.substr(colon + 1);
}

class Parser {
public:
    explicit Parser(std::string_view text) : text_(text) {}

    Document run() {
        Document document;

        skip_prologue();
        if (failed_) {
            document.error = error_;
            return document;
        }
        if (pos_ >= text_.size() || text_[pos_] != '<') {
            document.error = "no root element";
            return document;
        }

        Node root;
        if (!parse_element(root)) {
            document.error = error_.empty() ? "malformed XML" : error_;
            return document;
        }

        document.ok = true;
        document.root = std::move(root);
        return document;
    }

private:
    bool fail(std::string message) {
        if (!failed_) {
            failed_ = true;
            error_ = std::move(message) + " at offset " + std::to_string(pos_);
        }
        return false;
    }

    void skip_space() {
        while (pos_ < text_.size() && is_space(text_[pos_])) ++pos_;
    }

    bool starts_with(std::string_view prefix) const {
        return text_.compare(pos_, prefix.size(), prefix) == 0;
    }

    // Skips the XML declaration, comments, DOCTYPE and processing
    // instructions that may precede the root element.
    void skip_prologue() {
        for (;;) {
            skip_space();
            if (starts_with("<?")) {
                const std::size_t end = text_.find("?>", pos_);
                if (end == std::string_view::npos) {
                    fail("unterminated processing instruction");
                    return;
                }
                pos_ = end + 2;
            } else if (starts_with("<!--")) {
                if (!skip_comment()) return;
            } else if (starts_with("<!")) {
                const std::size_t end = text_.find('>', pos_);
                if (end == std::string_view::npos) {
                    fail("unterminated declaration");
                    return;
                }
                pos_ = end + 1;
            } else {
                return;
            }
        }
    }

    bool skip_comment() {
        const std::size_t end = text_.find("-->", pos_);
        if (end == std::string_view::npos) return fail("unterminated comment");
        pos_ = end + 3;
        return true;
    }

    std::string_view read_name() {
        const std::size_t start = pos_;
        if (pos_ < text_.size() && is_name_start(text_[pos_])) {
            ++pos_;
            while (pos_ < text_.size() && is_name_char(text_[pos_])) ++pos_;
        }
        return text_.substr(start, pos_ - start);
    }

    bool parse_element(Node& node) {
        if (pos_ >= text_.size() || text_[pos_] != '<') return fail("expected '<'");
        ++pos_;

        const std::string_view name = read_name();
        if (name.empty()) return fail("expected an element name");
        node.name = std::string(strip_prefix(name));

        // Attributes.
        for (;;) {
            skip_space();
            if (pos_ >= text_.size()) return fail("unterminated start tag");
            if (text_[pos_] == '>' || starts_with("/>")) break;

            const std::string_view attribute = read_name();
            if (attribute.empty()) return fail("expected an attribute name");
            skip_space();
            if (pos_ >= text_.size() || text_[pos_] != '=') return fail("expected '='");
            ++pos_;
            skip_space();
            if (pos_ >= text_.size() || (text_[pos_] != '"' && text_[pos_] != '\'')) {
                return fail("expected a quoted attribute value");
            }
            const char quote = text_[pos_++];
            const std::size_t start = pos_;
            while (pos_ < text_.size() && text_[pos_] != quote) ++pos_;
            if (pos_ >= text_.size()) return fail("unterminated attribute value");
            const std::string_view raw = text_.substr(start, pos_ - start);
            ++pos_;

            node.attributes.emplace_back(std::string(strip_prefix(attribute)),
                                         decode_entities(raw));
        }

        if (starts_with("/>")) {
            pos_ += 2;
            return true;
        }
        ++pos_;   // consume '>'

        // Content.
        std::string text;
        for (;;) {
            if (pos_ >= text_.size()) return fail("unterminated element '" + node.name + "'");

            if (starts_with("</")) {
                pos_ += 2;
                const std::string_view closing = read_name();
                if (std::string(strip_prefix(closing)) != node.name) {
                    return fail("closing tag '" + std::string(closing) + "' does not match '" +
                                node.name + "'");
                }
                skip_space();
                if (pos_ >= text_.size() || text_[pos_] != '>') return fail("expected '>'");
                ++pos_;
                node.text = decode_entities(text);
                return true;
            }

            if (starts_with("<!--")) {
                if (!skip_comment()) return false;
                continue;
            }

            if (starts_with("<![CDATA[")) {
                pos_ += 9;
                const std::size_t end = text_.find("]]>", pos_);
                if (end == std::string_view::npos) return fail("unterminated CDATA");
                text.append(text_.substr(pos_, end - pos_));   // never entity-decoded
                pos_ = end + 3;
                continue;
            }

            if (text_[pos_] == '<') {
                if (depth_ >= kMaxDepth) return fail("element nesting is too deep");
                ++depth_;
                Node child;
                const bool ok = parse_element(child);
                --depth_;
                if (!ok) return false;
                node.children.push_back(std::move(child));
                continue;
            }

            text += text_[pos_++];
        }
    }

    // Event XML nests a handful of levels; anything deeper is either not an
    // event record or is trying to exhaust the stack.
    static constexpr int kMaxDepth = 64;

    std::string_view text_;
    std::size_t pos_ = 0;
    int depth_ = 0;
    bool failed_ = false;
    std::string error_;
};

}  // namespace

std::string decode_entities(std::string_view text) {
    std::string out;
    out.reserve(text.size());

    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] != '&') {
            out += text[i];
            continue;
        }

        const std::size_t end = text.find(';', i + 1);
        // A bare '&', or a run longer than any real entity, is literal text.
        if (end == std::string_view::npos || end - i > 12) {
            out += text[i];
            continue;
        }

        const std::string_view entity = text.substr(i + 1, end - i - 1);
        if (entity == "lt") {
            out += '<';
        } else if (entity == "gt") {
            out += '>';
        } else if (entity == "amp") {
            out += '&';
        } else if (entity == "quot") {
            out += '"';
        } else if (entity == "apos") {
            out += '\'';
        } else if (entity.size() > 1 && entity[0] == '#') {
            const bool hex = entity[1] == 'x' || entity[1] == 'X';
            const std::string_view digits = entity.substr(hex ? 2 : 1);
            unsigned code_point = 0;
            bool valid = !digits.empty();
            for (const char c : digits) {
                int value = -1;
                if (c >= '0' && c <= '9') {
                    value = c - '0';
                } else if (hex && c >= 'a' && c <= 'f') {
                    value = c - 'a' + 10;
                } else if (hex && c >= 'A' && c <= 'F') {
                    value = c - 'A' + 10;
                }
                if (value < 0 || code_point > 0x10FFFF) {
                    valid = false;
                    break;
                }
                code_point = code_point * (hex ? 16u : 10u) + static_cast<unsigned>(value);
            }
            if (!valid || code_point > 0x10FFFF) {
                out += text[i];
                continue;
            }
            append_utf8(out, code_point);
        } else {
            // Unknown entity: keep it verbatim rather than dropping content.
            out += text[i];
            continue;
        }

        i = end;
    }
    return out;
}

const Node* Node::child(std::string_view child_name) const {
    for (const Node& node : children) {
        if (node.name == child_name) return &node;
    }
    return nullptr;
}

std::vector<const Node*> Node::children_named(std::string_view child_name) const {
    std::vector<const Node*> result;
    for (const Node& node : children) {
        if (node.name == child_name) result.push_back(&node);
    }
    return result;
}

const std::string* Node::attribute(std::string_view attribute_name) const {
    for (const auto& entry : attributes) {
        if (entry.first == attribute_name) return &entry.second;
    }
    return nullptr;
}

const Node* Node::find(std::string_view path) const {
    const Node* current = this;
    std::size_t start = 0;
    while (start <= path.size()) {
        const std::size_t slash = path.find('/', start);
        const std::string_view step =
            path.substr(start, slash == std::string_view::npos ? std::string_view::npos
                                                               : slash - start);
        if (step.empty()) break;
        current = current->child(step);
        if (current == nullptr) return nullptr;
        if (slash == std::string_view::npos) break;
        start = slash + 1;
    }
    return current;
}

Document parse(std::string_view text) {
    Parser parser(text);
    return parser.run();
}

}  // namespace postmortem::xml
