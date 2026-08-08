// Turning sampled return addresses into something readable.
//
// Two layers, best first:
//   1. DbgHelp SymFromAddr, which gives a function name whenever a PDB or the
//      module's export table can supply one.
//   2. A module map, so an address with no symbol still reads as
//      "ntoskrnl.exe+0x1a2c40" rather than a bare number.
//
// Kernel addresses are attributed from EnumDeviceDrivers; user addresses from
// the owning process's module list. Never call this from an ETW callback -
// DbgHelp is not thread-safe and symbol lookups are far too slow for the
// sampling path.

#pragma once

#include <cstdint>
#include <string>

namespace postmortem::platform {

class SymbolResolver {
public:
    SymbolResolver() = default;
    ~SymbolResolver();

    SymbolResolver(const SymbolResolver&) = delete;
    SymbolResolver& operator=(const SymbolResolver&) = delete;

    // `process_id` is the process the address belongs to; ignored for kernel
    // addresses. Results are cached, so repeated frames across samples are
    // resolved once.
    [[nodiscard]] std::string resolve(std::uint64_t address, std::uint32_t process_id);

    // True once anything has been resolved to an actual function name, so the
    // caller can say whether symbols were available at all.
    [[nodiscard]] bool any_named() const { return any_named_; }

    [[nodiscard]] static bool is_kernel_address(std::uint64_t address) {
        return address >= 0xFFFF800000000000ull;
    }

private:
    struct Impl;
    Impl* impl_ = nullptr;
    bool any_named_ = false;

    void ensure();
};

}  // namespace postmortem::platform
