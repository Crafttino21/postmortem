#include "core/events/event.hpp"

#include "core/input/values.hpp"
#include "core/text/format.hpp"

namespace postmortem::events {
namespace {

std::optional<std::uint64_t> to_number(const std::string& text) {
    const input::IntegerResult parsed = input::parse_u64(text);
    if (!parsed.ok) return std::nullopt;
    return parsed.value;
}

void collect_data(const xml::Node& parent, Event& event) {
    for (const xml::Node* data : parent.children_named("Data")) {
        const std::string* name = data->attribute("Name");
        // Unnamed <Data> elements appear in older schemas; index them so
        // nothing is dropped silently.
        event.data.emplace_back(name != nullptr ? *name
                                                : std::to_string(event.data.size()),
                                data->text);
    }
}

}  // namespace

const std::string* Event::value(std::string_view name) const {
    for (const auto& entry : data) {
        if (entry.first == name) return &entry.second;
    }
    return nullptr;
}

std::optional<std::uint64_t> Event::number(std::string_view name) const {
    const std::string* text = value(name);
    if (text == nullptr) return std::nullopt;
    return to_number(*text);
}

Event from_xml(const xml::Node& event_node) {
    Event event;

    if (const xml::Node* system = event_node.child("System")) {
        if (const xml::Node* provider = system->child("Provider")) {
            if (const std::string* name = provider->attribute("Name")) event.provider = *name;
        }
        if (const xml::Node* id = system->child("EventID")) {
            if (const auto value = to_number(id->text)) {
                event.event_id = static_cast<unsigned>(*value);
            }
        }
        if (const xml::Node* level = system->child("Level")) {
            if (const auto value = to_number(level->text)) {
                event.level = static_cast<unsigned>(*value);
            }
        }
        if (const xml::Node* task = system->child("Task")) {
            if (const auto value = to_number(task->text)) {
                event.task = static_cast<unsigned>(*value);
            }
        }
        if (const xml::Node* channel = system->child("Channel")) event.channel = channel->text;
        if (const xml::Node* computer = system->child("Computer")) {
            event.computer = computer->text;
        }
        if (const xml::Node* record = system->child("EventRecordID")) {
            if (const auto value = to_number(record->text)) event.record_id = *value;
        }
        if (const xml::Node* keywords = system->child("Keywords")) {
            if (const auto value = to_number(keywords->text)) event.keywords = *value;
        }
        if (const xml::Node* created = system->child("TimeCreated")) {
            if (const std::string* time = created->attribute("SystemTime")) {
                event.time_text = *time;
                if (const auto instant = text::parse_iso8601(*time)) {
                    event.time = instant->seconds;
                    event.time_nanoseconds = instant->nanoseconds;
                }
            }
        }
    }

    // EventData is the usual container; UserData appears on some providers.
    if (const xml::Node* data = event_node.child("EventData")) collect_data(*data, event);
    if (const xml::Node* user = event_node.child("UserData")) {
        collect_data(*user, event);
        // UserData wraps its fields in a provider-specific element one level
        // down; take those too rather than reporting an empty event.
        for (const xml::Node& child : user->children) {
            collect_data(child, event);
            for (const xml::Node& leaf : child.children) {
                if (leaf.children.empty() && !leaf.text.empty()) {
                    event.data.emplace_back(leaf.name, leaf.text);
                }
            }
        }
    }

    return event;
}

std::optional<Event> from_xml_text(std::string_view text) {
    const xml::Document document = xml::parse(text);
    if (!document.ok) return std::nullopt;

    Event event = from_xml(document.root);
    event.xml = std::string(text);
    return event;
}

}  // namespace postmortem::events
