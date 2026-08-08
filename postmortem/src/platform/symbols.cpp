#include "platform/symbols.hpp"

#include <windows.h>

#include <dbghelp.h>
#include <psapi.h>

#include <algorithm>
#include <map>
#include <unordered_map>
#include <vector>

#include "core/text/format.hpp"
#include "platform/strings.hpp"

namespace postmortem::platform {
namespace {

struct ModuleRange {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::string name;

    [[nodiscard]] bool contains(std::uint64_t address) const {
        return address >= base && address < base + size;
    }
};

std::string base_name(const std::wstring& path) {
    const std::size_t slash = path.find_last_of(L"\\/");
    const std::wstring name = slash == std::wstring::npos ? path : path.substr(slash + 1);
    return to_utf8(name);
}

// Kernel modules, so a kernel frame reads as "ntoskrnl.exe+0x...". There is no
// way to read kernel *memory* from user mode, but the load addresses are
// published.
std::vector<ModuleRange> enumerate_kernel_modules() {
    std::vector<ModuleRange> modules;

    DWORD needed = 0;
    if (::EnumDeviceDrivers(nullptr, 0, &needed) == FALSE || needed == 0) return modules;

    std::vector<LPVOID> bases(needed / sizeof(LPVOID) + 1);
    if (::EnumDeviceDrivers(bases.data(), static_cast<DWORD>(bases.size() * sizeof(LPVOID)),
                            &needed) == FALSE) {
        return modules;
    }
    bases.resize(needed / sizeof(LPVOID));

    for (LPVOID base : bases) {
        if (base == nullptr) continue;
        wchar_t name[MAX_PATH] = {};
        if (::GetDeviceDriverBaseNameW(base, name, MAX_PATH) == 0) continue;

        ModuleRange range;
        range.base = reinterpret_cast<std::uint64_t>(base);
        range.name = to_utf8(name);
        modules.push_back(std::move(range));
    }

    // EnumDeviceDrivers gives bases but no sizes; derive each module's extent
    // from the next one up. The last gets a nominal span.
    std::sort(modules.begin(), modules.end(),
              [](const ModuleRange& a, const ModuleRange& b) { return a.base < b.base; });
    for (std::size_t i = 0; i < modules.size(); ++i) {
        modules[i].size = (i + 1 < modules.size()) ? modules[i + 1].base - modules[i].base
                                                   : 0x200000;
    }
    return modules;
}

std::vector<ModuleRange> enumerate_process_modules(HANDLE process) {
    std::vector<ModuleRange> modules;
    if (process == nullptr) return modules;

    DWORD needed = 0;
    if (::EnumProcessModulesEx(process, nullptr, 0, &needed, LIST_MODULES_ALL) == FALSE ||
        needed == 0) {
        return modules;
    }

    std::vector<HMODULE> handles(needed / sizeof(HMODULE) + 1);
    if (::EnumProcessModulesEx(process, handles.data(),
                               static_cast<DWORD>(handles.size() * sizeof(HMODULE)), &needed,
                               LIST_MODULES_ALL) == FALSE) {
        return modules;
    }
    handles.resize(needed / sizeof(HMODULE));

    for (HMODULE handle : handles) {
        MODULEINFO info{};
        if (::GetModuleInformation(process, handle, &info, sizeof(info)) == FALSE) continue;

        wchar_t path[MAX_PATH] = {};
        if (::GetModuleFileNameExW(process, handle, path, MAX_PATH) == 0) continue;

        ModuleRange range;
        range.base = reinterpret_cast<std::uint64_t>(info.lpBaseOfDll);
        range.size = info.SizeOfImage;
        range.name = base_name(path);
        modules.push_back(std::move(range));
    }
    return modules;
}

}  // namespace

struct SymbolResolver::Impl {
    std::vector<ModuleRange> kernel_modules;
    bool kernel_loaded = false;

    struct ProcessEntry {
        HANDLE handle = nullptr;
        bool symbols_initialised = false;
        std::vector<ModuleRange> modules;
    };
    std::map<std::uint32_t, ProcessEntry> processes;

    // (pid, address) -> text. Sampling revisits the same frames constantly, so
    // without this every frame would cost a DbgHelp lookup.
    std::unordered_map<std::uint64_t, std::string> cache;

    ~Impl() {
        for (auto& [pid, entry] : processes) {
            (void)pid;
            if (entry.symbols_initialised) ::SymCleanup(entry.handle);
            if (entry.handle != nullptr) ::CloseHandle(entry.handle);
        }
    }
};

SymbolResolver::~SymbolResolver() {
    delete impl_;
    impl_ = nullptr;
}

void SymbolResolver::ensure() {
    if (impl_ != nullptr) return;
    impl_ = new Impl();

    // Do not go looking on symbol servers: a live view must not stall for
    // seconds downloading PDBs. Exports and any PDB already beside the binary
    // are enough to make most frames readable.
    ::SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_NO_PROMPTS |
                    SYMOPT_FAIL_CRITICAL_ERRORS);
}

std::string SymbolResolver::resolve(std::uint64_t address, std::uint32_t process_id) {
    ensure();
    if (address == 0) return "0x0";

    const bool kernel = is_kernel_address(address);
    const std::uint64_t key =
        (static_cast<std::uint64_t>(kernel ? 0u : process_id) << 48) ^ address;
    if (const auto found = impl_->cache.find(key); found != impl_->cache.end()) {
        return found->second;
    }

    std::string text;

    if (kernel) {
        if (!impl_->kernel_loaded) {
            impl_->kernel_modules = enumerate_kernel_modules();
            impl_->kernel_loaded = true;
        }
        for (const ModuleRange& module : impl_->kernel_modules) {
            if (!module.contains(address)) continue;
            text = module.name + "+" + text::to_hex(address - module.base, 0);
            break;
        }
    } else {
        Impl::ProcessEntry& entry = impl_->processes[process_id];
        if (entry.handle == nullptr) {
            entry.handle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
            if (entry.handle != nullptr) {
                entry.modules = enumerate_process_modules(entry.handle);
                // invade = TRUE loads symbols for every module already mapped,
                // which is what makes SymFromAddr able to answer at all.
                entry.symbols_initialised =
                    ::SymInitializeW(entry.handle, nullptr, TRUE) != FALSE;
            }
        }

        if (entry.symbols_initialised) {
            // SYMBOL_INFO is variable-length: the name lives past the struct.
            alignas(SYMBOL_INFOW) std::byte buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME *
                                                                              sizeof(wchar_t)]{};
            auto* symbol = reinterpret_cast<SYMBOL_INFOW*>(buffer);
            symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
            symbol->MaxNameLen = MAX_SYM_NAME;

            DWORD64 displacement = 0;
            if (::SymFromAddrW(entry.handle, address, &displacement, symbol) != FALSE) {
                std::string name = to_utf8(std::wstring_view(symbol->Name, symbol->NameLen));
                if (!name.empty()) {
                    text = name;
                    if (displacement != 0) text += "+" + text::to_hex(displacement, 0);
                    any_named_ = true;
                }
            }
        }

        if (text.empty()) {
            for (const ModuleRange& module : entry.modules) {
                if (!module.contains(address)) continue;
                text = module.name + "+" + text::to_hex(address - module.base, 0);
                break;
            }
        } else {
            // Prefix the module so two functions of the same name in different
            // binaries stay distinguishable.
            for (const ModuleRange& module : entry.modules) {
                if (!module.contains(address)) continue;
                std::string stem = module.name;
                if (const std::size_t dot = stem.find_last_of('.');
                    dot != std::string::npos) {
                    stem.erase(dot);
                }
                text = stem + "!" + text;
                break;
            }
        }
    }

    if (text.empty()) text = text::to_hex(address, 16);

    impl_->cache.emplace(key, text);
    return text;
}

}  // namespace postmortem::platform
