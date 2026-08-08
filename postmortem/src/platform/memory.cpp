#include "platform/memory.hpp"

#include <windows.h>

#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cctype>

#include "platform/strings.hpp"

namespace postmortem::platform {
namespace {

std::string last_error_text() {
    const DWORD code = ::GetLastError();
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

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

std::string base_name(const std::wstring& path) {
    const std::size_t slash = path.find_last_of(L"\\/");
    return to_utf8(slash == std::wstring::npos ? path : path.substr(slash + 1));
}

}  // namespace

ProcessMemory::~ProcessMemory() {
    close();
}

ProcessTarget ProcessMemory::open(std::uint32_t process_id) {
    close();

    ProcessTarget target;
    target.process_id = process_id;

    // Read-only rights only: nothing here writes to the target, and asking for
    // less makes the open succeed against more processes.
    const HANDLE handle = ::OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (handle == nullptr) {
        target.error = "cannot open process " + std::to_string(process_id) + ": " +
                       last_error_text();
        if (::GetLastError() == ERROR_ACCESS_DENIED) {
            target.error +=
                " (a protected or higher-integrity process cannot be read; try an elevated "
                "prompt, and note that anti-cheat and PPL processes refuse regardless)";
        }
        return target;
    }
    handle_ = handle;

    wchar_t path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    if (::QueryFullProcessImageNameW(handle, 0, path, &size) != FALSE) {
        target.name = base_name(std::wstring(path, size));
    }

    target.ok = true;
    return target;
}

void ProcessMemory::close() {
    if (handle_ != nullptr) {
        ::CloseHandle(handle_);
        handle_ = nullptr;
    }
}

bool ProcessMemory::read(std::uint64_t address, std::size_t length,
                         std::vector<std::uint8_t>& out, std::size_t& read_bytes) const {
    read_bytes = 0;
    out.assign(length, 0);
    if (handle_ == nullptr || length == 0) return false;

    SIZE_T transferred = 0;
    const BOOL ok = ::ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(address), out.data(),
                                        length, &transferred);
    read_bytes = static_cast<std::size_t>(transferred);

    // A partial read still fills the prefix, which is worth showing.
    return ok != FALSE || transferred > 0;
}

std::vector<MemoryRegion> ProcessMemory::regions() const {
    std::vector<MemoryRegion> found;
    if (handle_ == nullptr) return found;

    std::uint64_t address = 0;
    MEMORY_BASIC_INFORMATION info{};
    while (::VirtualQueryEx(handle_, reinterpret_cast<LPCVOID>(address), &info, sizeof(info)) ==
           sizeof(info)) {
        const auto base = reinterpret_cast<std::uint64_t>(info.BaseAddress);
        const auto size = static_cast<std::uint64_t>(info.RegionSize);
        if (size == 0) break;

        if (info.State == MEM_COMMIT) {
            MemoryRegion region;
            region.base = base;
            region.size = size;

            const DWORD protect = info.Protect & 0xFF;
            const bool guarded = (info.Protect & PAGE_GUARD) != 0 ||
                                 (info.Protect & PAGE_NOACCESS) != 0;
            region.readable =
                !guarded && (protect == PAGE_READONLY || protect == PAGE_READWRITE ||
                             protect == PAGE_WRITECOPY || protect == PAGE_EXECUTE_READ ||
                             protect == PAGE_EXECUTE_READWRITE ||
                             protect == PAGE_EXECUTE_WRITECOPY);
            region.writable = protect == PAGE_READWRITE || protect == PAGE_WRITECOPY ||
                              protect == PAGE_EXECUTE_READWRITE ||
                              protect == PAGE_EXECUTE_WRITECOPY;
            region.executable = protect == PAGE_EXECUTE || protect == PAGE_EXECUTE_READ ||
                                protect == PAGE_EXECUTE_READWRITE ||
                                protect == PAGE_EXECUTE_WRITECOPY;
            region.image = info.Type == MEM_IMAGE;
            region.is_private = info.Type == MEM_PRIVATE;

            if (region.image) {
                wchar_t name[MAX_PATH] = {};
                if (::GetMappedFileNameW(handle_, info.BaseAddress, name, MAX_PATH) != 0) {
                    region.module = base_name(name);
                }
            }
            found.push_back(std::move(region));
        }

        const std::uint64_t next = base + size;
        if (next <= address) break;   // guard against a non-advancing walk
        address = next;
    }
    return found;
}

std::uint64_t ProcessMemory::module_base(const std::string& name) const {
    if (handle_ == nullptr) return 0;

    DWORD needed = 0;
    if (::EnumProcessModulesEx(handle_, nullptr, 0, &needed, LIST_MODULES_ALL) == FALSE) {
        return 0;
    }

    std::vector<HMODULE> handles(needed / sizeof(HMODULE) + 1);
    if (::EnumProcessModulesEx(handle_, handles.data(),
                               static_cast<DWORD>(handles.size() * sizeof(HMODULE)), &needed,
                               LIST_MODULES_ALL) == FALSE) {
        return 0;
    }
    handles.resize(needed / sizeof(HMODULE));

    const std::string wanted = lower(name);
    for (HMODULE module : handles) {
        wchar_t path[MAX_PATH] = {};
        if (::GetModuleFileNameExW(handle_, module, path, MAX_PATH) == 0) continue;
        if (lower(base_name(path)) != wanted) continue;

        MODULEINFO info{};
        if (::GetModuleInformation(handle_, module, &info, sizeof(info)) == FALSE) continue;
        return reinterpret_cast<std::uint64_t>(info.lpBaseOfDll);
    }
    return 0;
}

ProcessLookup find_process(const std::string& id_or_name) {
    ProcessLookup lookup;

    // All digits means a pid.
    if (!id_or_name.empty() &&
        std::all_of(id_or_name.begin(), id_or_name.end(),
                    [](char c) { return c >= '0' && c <= '9'; })) {
        lookup.ok = true;
        lookup.process_id = static_cast<std::uint32_t>(std::stoul(id_or_name));
        return lookup;
    }

    const HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        lookup.error = "cannot enumerate processes: " + last_error_text();
        return lookup;
    }

    const std::string wanted = lower(id_or_name);
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (::Process32FirstW(snapshot, &entry) != FALSE) {
        do {
            const std::string name = to_utf8(entry.szExeFile);
            const std::string name_lower = lower(name);
            if (name_lower == wanted || name_lower == wanted + ".exe") {
                lookup.candidates.emplace_back(entry.th32ProcessID, name);
            }
        } while (::Process32NextW(snapshot, &entry) != FALSE);
    }
    ::CloseHandle(snapshot);

    if (lookup.candidates.empty()) {
        lookup.error = "no process matches '" + id_or_name + "'";
        return lookup;
    }
    if (lookup.candidates.size() > 1) {
        // Picking one silently would attach the watch to an arbitrary
        // instance, which is worse than asking.
        lookup.error = std::to_string(lookup.candidates.size()) + " processes match '" +
                       id_or_name + "'; pass the pid instead";
        return lookup;
    }

    lookup.ok = true;
    lookup.process_id = lookup.candidates.front().first;
    lookup.name = lookup.candidates.front().second;
    return lookup;
}

}  // namespace postmortem::platform
