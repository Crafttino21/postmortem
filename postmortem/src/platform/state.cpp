#include "platform/state.hpp"

#include <windows.h>

#include <shlobj.h>

#include <algorithm>

#include "core/json/reader.hpp"
#include "core/json/writer.hpp"
#include "platform/file.hpp"
#include "platform/strings.hpp"

namespace postmortem::platform {
namespace {

constexpr int kSchemaVersion = 1;

std::string program_data() {
    PWSTR path = nullptr;
    if (::SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &path) != S_OK ||
        path == nullptr) {
        return {};
    }
    std::string result = to_utf8(path);
    ::CoTaskMemFree(path);
    return result;
}

bool write_file_atomically(const std::string& path, const std::string& content,
                           std::string& error) {
    const std::string temporary = path + ".tmp";
    const std::wstring wide_temporary = to_utf16(temporary);

    const HANDLE file = ::CreateFileW(wide_temporary.c_str(), GENERIC_WRITE, 0, nullptr,
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = "cannot create '" + temporary + "' (error " +
                std::to_string(::GetLastError()) + ")";
        return false;
    }

    DWORD written = 0;
    const BOOL ok = ::WriteFile(file, content.data(), static_cast<DWORD>(content.size()),
                                &written, nullptr);
    // Flush before the rename: a rename that lands before the data reaches
    // disk would survive a crash as an empty snapshot.
    ::FlushFileBuffers(file);
    ::CloseHandle(file);

    if (ok == FALSE || written != content.size()) {
        error = "cannot write '" + temporary + "'";
        ::DeleteFileW(wide_temporary.c_str());
        return false;
    }

    const std::wstring wide_path = to_utf16(path);
    if (::MoveFileExW(wide_temporary.c_str(), wide_path.c_str(),
                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE) {
        error = "cannot replace '" + path + "' (error " + std::to_string(::GetLastError()) + ")";
        ::DeleteFileW(wide_temporary.c_str());
        return false;
    }
    return true;
}

}  // namespace

std::string state_directory() {
    const std::string base = program_data();
    if (base.empty()) return {};

    const std::string directory = base + "\\postmortem";
    const std::wstring wide = to_utf16(directory);
    if (::CreateDirectoryW(wide.c_str(), nullptr) == FALSE) {
        if (::GetLastError() != ERROR_ALREADY_EXISTS) return {};
    }
    return directory;
}

StateStore::StateStore() {
    const std::string directory = state_directory();
    if (!directory.empty()) path_ = directory + "\\state.json";
}

StateLoad StateStore::load() {
    StateLoad result;
    if (path_.empty()) {
        result.error = "cannot locate %ProgramData%";
        return result;
    }

    const FileResult file = read_file(path_);
    if (!file.ok) {
        // An absent file is the normal first-run case.
        result.missing = true;
        result.ok = true;
        return result;
    }

    const std::string text(file.bytes.begin(), file.bytes.end());
    const json::ParseResult parsed = json::parse(text);
    if (!parsed.ok) {
        result.error = "the state file is not valid JSON (" + parsed.error +
                       "); refusing to guess at its contents";
        return result;
    }

    entries_.clear();
    for (const json::Value& item : parsed.value["entries"].as_array()) {
        StateEntry entry;
        entry.mitigation = item["mitigation"].as_string();
        entry.kind = item["kind"].as_string();
        entry.scope = item["scope"].as_string();
        entry.scope_name = item["scope_name"].as_string();
        entry.key = item["key"].as_string();
        entry.previous_present = item["previous_present"].as_bool(true);
        entry.previous_ac = static_cast<std::uint32_t>(item["previous_ac"].as_uint());
        entry.previous_dc = static_cast<std::uint32_t>(item["previous_dc"].as_uint());
        entry.applied_at = item["applied_at"].as_int();
        if (!entry.mitigation.empty()) entries_.push_back(std::move(entry));
    }

    result.ok = true;
    return result;
}

StateSave StateStore::save() const {
    StateSave result;
    result.path = path_;
    if (path_.empty()) {
        result.error = "cannot locate %ProgramData%";
        return result;
    }

    json::Writer writer(true);
    writer.begin_object();
    writer.member_int("schema_version", kSchemaVersion);
    writer.member("tool", "postmortem");
    writer.key("entries").begin_array();
    for (const StateEntry& entry : entries_) {
        writer.begin_object();
        writer.member("mitigation", entry.mitigation);
        writer.member("kind", entry.kind);
        writer.member("scope", entry.scope);
        writer.member("scope_name", entry.scope_name);
        writer.member("key", entry.key);
        writer.member_bool("previous_present", entry.previous_present);
        writer.member_uint("previous_ac", entry.previous_ac);
        writer.member_uint("previous_dc", entry.previous_dc);
        writer.member_int("applied_at", entry.applied_at);
        writer.end_object();
    }
    writer.end_array();
    writer.end_object();

    const std::string content = writer.take() + "\n";
    if (!write_file_atomically(path_, content, result.error)) return result;

    result.ok = true;
    return result;
}

void StateStore::add(const StateEntry& entry) {
    // One snapshot per (mitigation, scope, key): re-applying must not bury the
    // value that was there before the *first* apply.
    const auto existing = std::find_if(entries_.begin(), entries_.end(),
                                       [&](const StateEntry& candidate) {
                                           return candidate.mitigation == entry.mitigation &&
                                                  candidate.scope == entry.scope &&
                                                  candidate.key == entry.key;
                                       });
    if (existing != entries_.end()) return;
    entries_.push_back(entry);
}

void StateStore::remove(std::string_view mitigation) {
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
                                  [&](const StateEntry& entry) {
                                      return entry.mitigation == mitigation;
                                  }),
                   entries_.end());
}

std::vector<StateEntry> StateStore::entries_for(std::string_view mitigation) const {
    std::vector<StateEntry> result;
    for (const StateEntry& entry : entries_) {
        if (entry.mitigation == mitigation) result.push_back(entry);
    }
    return result;
}

}  // namespace postmortem::platform
