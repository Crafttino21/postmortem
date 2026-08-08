// A minimal XML reader for rendered event records.
//
// EvtRender(EvtRenderEventXml) hands back the whole event as XML, which is the
// only rendering that preserves the EventData field *names* - the typed
// EvtRenderEventValues path gives values in schema order with no names, and
// the WHEA schema differs between Windows versions. Parsing the XML is
// therefore the robust route, and it keeps the event model in core/ where it
// can be tested against captured XML with no event log present.
//
// This is not a general XML implementation. It handles what the Windows event
// schema actually emits: elements, attributes, text, self-closing tags,
// comments, CDATA, the five predefined entities and numeric character
// references. It rejects anything else rather than guessing - a DTD, a
// processing instruction other than the declaration, or malformed markup.

#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace postmortem::xml {

struct Node {
    // Namespace prefixes are stripped: the event schema uses them
    // inconsistently and nothing here needs to distinguish them.
    std::string name;
    std::vector<std::pair<std::string, std::string>> attributes;
    std::string text;   // direct text content, entity-decoded
    std::vector<Node> children;

    [[nodiscard]] const Node* child(std::string_view child_name) const;
    [[nodiscard]] std::vector<const Node*> children_named(std::string_view child_name) const;
    [[nodiscard]] const std::string* attribute(std::string_view attribute_name) const;

    // Walks a slash-separated path, e.g. "System/Provider". Returns nullptr if
    // any step is missing.
    [[nodiscard]] const Node* find(std::string_view path) const;
};

struct Document {
    bool ok = false;
    Node root;
    std::string error;
};

[[nodiscard]] Document parse(std::string_view text);

// Exposed for tests: decodes &lt; &gt; &amp; &quot; &apos; and &#NN; / &#xNN;.
// An unrecognised entity is left verbatim rather than dropped, so nothing is
// silently lost from a field that goes on to be shown to the user.
[[nodiscard]] std::string decode_entities(std::string_view text);

}  // namespace postmortem::xml
