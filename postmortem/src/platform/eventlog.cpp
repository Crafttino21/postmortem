#include "platform/eventlog.hpp"

#include <windows.h>

#include <winevt.h>

#include <algorithm>
#include <chrono>

#include "core/text/format.hpp"
#include "platform/strings.hpp"

namespace postmortem::platform {
namespace {

std::string last_error_text(DWORD code) {
    LPWSTR buffer = nullptr;
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::string message;
    if (length > 0 && buffer != nullptr) {
        message = trim(to_utf8(std::wstring_view(buffer, length)));
    }
    if (buffer != nullptr) ::LocalFree(buffer);
    if (message.empty()) message = "error " + std::to_string(code);
    return message;
}

std::string last_error_text() {
    return last_error_text(::GetLastError());
}

// RAII for EVT_HANDLE. The subscription in §4.7 in particular "must be torn
// down properly", and the query path has four early returns.
class EvtHandle {
public:
    EvtHandle() = default;
    explicit EvtHandle(EVT_HANDLE handle) : handle_(handle) {}
    ~EvtHandle() { reset(); }

    EvtHandle(const EvtHandle&) = delete;
    EvtHandle& operator=(const EvtHandle&) = delete;
    EvtHandle(EvtHandle&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
    EvtHandle& operator=(EvtHandle&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    void reset(EVT_HANDLE handle = nullptr) {
        if (handle_ != nullptr) ::EvtClose(handle_);
        handle_ = handle;
    }

    [[nodiscard]] EVT_HANDLE get() const { return handle_; }
    explicit operator bool() const { return handle_ != nullptr; }

private:
    EVT_HANDLE handle_ = nullptr;
};

std::string escape_xpath_literal(const std::string& value) {
    // Provider names come from our own tables, but quote them defensively so a
    // future caller cannot inject query syntax.
    std::string out;
    for (const char c : value) {
        if (c == '\'') continue;
        out += c;
    }
    return out;
}

// Builds the XPath filter. Filtering in the query rather than in C++ matters:
// the System channel holds hundreds of thousands of records and the service
// can index it.
//
// A bare XPath selector, not a <QueryList> wrapper. A QueryList carries its
// own Path attribute, and EvtQuery gives that precedence over the path
// argument - so a QueryList naming Path='System' silently reads the live
// channel even when EvtQueryFilePath was requested, which would hand someone
// analysing an exported log their own machine's records instead.
std::wstring build_query(const EventQuery& query) {
    std::string conditions;

    if (!query.providers.empty()) {
        std::string providers;
        for (const std::string& provider : query.providers) {
            if (!providers.empty()) providers += " or ";
            providers += "@Name='" + escape_xpath_literal(provider) + "'";
        }
        conditions += "Provider[" + providers + "]";
    }

    if (query.since > 0) {
        // EvtQuery understands an absolute ISO-8601 SystemTime comparison.
        const std::string since = text::format_utc(query.since);
        // format_utc yields "YYYY-MM-DD HH:MM:SSZ"; the query wants a 'T'.
        std::string iso = since;
        if (iso.size() > 10) iso[10] = 'T';
        if (!conditions.empty()) conditions += " and ";
        conditions += "TimeCreated[@SystemTime>='" + iso + "']";
    }

    if (conditions.empty()) return to_utf16("*");
    return to_utf16("*[System[" + conditions + "]]");
}

// Renders one event to XML. Returns an empty string on failure; the caller
// records a warning rather than aborting the whole query.
std::string render_event(EVT_HANDLE event) {
    DWORD needed = 0;
    DWORD property_count = 0;
    if (::EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &needed, &property_count) !=
            FALSE ||
        ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return {};
    }

    std::wstring buffer(needed / sizeof(wchar_t) + 1, L'\0');
    if (::EvtRender(nullptr, event, EvtRenderEventXml, needed, buffer.data(), &needed,
                    &property_count) == FALSE) {
        return {};
    }

    // needed is a byte count; trim to the actual string.
    const std::size_t characters = needed / sizeof(wchar_t);
    std::wstring_view view(buffer.data(), std::min(characters, buffer.size()));
    while (!view.empty() && view.back() == L'\0') view.remove_suffix(1);
    return to_utf8(view);
}

constexpr DWORD kBatchSize = 64;

}  // namespace

EventQueryResult query_events(const EventQuery& query) {
    EventQueryResult result;

    const std::wstring query_text = build_query(query);
    const DWORD flags = query.evtx_path.empty()
                            ? (EvtQueryChannelPath | EvtQueryReverseDirection)
                            : (EvtQueryFilePath | EvtQueryReverseDirection);
    const std::wstring path =
        query.evtx_path.empty() ? std::wstring(L"System") : to_utf16(query.evtx_path);

    // Reverse direction: newest first, so `--since` and `limit` cut the recent
    // end of the log rather than the ancient one.
    EvtHandle handle(::EvtQuery(nullptr, path.c_str(), query_text.c_str(), flags));
    if (!handle) {
        const DWORD code = ::GetLastError();
        result.error = query.evtx_path.empty()
                           ? "cannot query the System event log: " + last_error_text(code)
                           : "cannot open '" + query.evtx_path + "': " + last_error_text(code);
        if (code == ERROR_ACCESS_DENIED) {
            result.error += " (reading the System channel normally works as a standard user; "
                            "this looks like a policy restriction)";
        }
        return result;
    }

    for (;;) {
        EVT_HANDLE batch[kBatchSize] = {};
        DWORD returned = 0;
        if (::EvtNext(handle.get(), kBatchSize, batch, INFINITE, 0, &returned) == FALSE) {
            const DWORD code = ::GetLastError();
            if (code != ERROR_NO_MORE_ITEMS) {
                result.warnings.push_back("event enumeration stopped early: " +
                                          last_error_text(code));
            }
            break;
        }

        bool reached_limit = false;
        for (DWORD i = 0; i < returned; ++i) {
            const std::string xml = render_event(batch[i]);
            ::EvtClose(batch[i]);
            batch[i] = nullptr;

            if (xml.empty()) {
                result.warnings.emplace_back("one record could not be rendered and was skipped");
                continue;
            }
            if (const auto event = events::from_xml_text(xml)) {
                result.events.push_back(*event);
            } else {
                result.warnings.emplace_back("one record rendered to XML that could not be parsed");
            }

            if (query.limit > 0 && result.events.size() >= query.limit) {
                reached_limit = true;
                // Close whatever the batch still holds before leaving.
                for (DWORD j = i + 1; j < returned; ++j) ::EvtClose(batch[j]);
                break;
            }
        }
        if (reached_limit || returned == 0) break;
    }

    // Restore chronological order; the query ran newest-first only to bound
    // the work.
    std::reverse(result.events.begin(), result.events.end());

    result.ok = true;
    return result;
}

SubscriptionResult subscribe_events(const std::vector<std::string>& providers,
                                    const EventCallback& on_event,
                                    const std::function<bool()>& keep_going) {
    SubscriptionResult result;

    struct Context {
        const EventCallback* callback;
        HANDLE signal;
    };

    const HANDLE signal = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (signal == nullptr) {
        result.error = "cannot create the wake-up event: " + last_error_text();
        return result;
    }

    Context context{&on_event, signal};

    // A synchronous subscription would need a waitable handle per record; the
    // callback form is simpler and is what EvtSubscribe is designed for.
    const auto callback = [](EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID user_context,
                             EVT_HANDLE event) -> DWORD {
        auto* ctx = static_cast<Context*>(user_context);
        if (action == EvtSubscribeActionDeliver && ctx != nullptr) {
            const std::string xml = render_event(event);
            if (!xml.empty()) {
                if (const auto parsed = events::from_xml_text(xml)) {
                    (*ctx->callback)(*parsed);
                }
            }
        }
        return ERROR_SUCCESS;
    };

    EventQuery query;
    query.providers = providers;
    const std::wstring query_text = build_query(query);

    EvtHandle subscription(::EvtSubscribe(nullptr, nullptr, L"System", query_text.c_str(),
                                          nullptr, &context,
                                          static_cast<EVT_SUBSCRIBE_CALLBACK>(callback),
                                          EvtSubscribeToFutureEvents));
    if (!subscription) {
        result.error = "cannot subscribe to the System channel: " + last_error_text();
        ::CloseHandle(signal);
        return result;
    }

    // Poll the stop condition rather than blocking forever, so Ctrl+C is
    // noticed promptly and the subscription is closed on the way out.
    while (keep_going()) {
        ::WaitForSingleObject(signal, 200);
    }

    subscription.reset();   // tear the subscription down before returning
    ::CloseHandle(signal);

    result.ok = true;
    return result;
}

bool is_elevated() {
    HANDLE token = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE) return false;

    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const BOOL ok =
        ::GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    ::CloseHandle(token);

    return ok != FALSE && elevation.TokenIsElevated != 0;
}

}  // namespace postmortem::platform
