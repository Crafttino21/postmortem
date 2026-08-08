#include "platform/arch.hpp"

#include <windows.h>

namespace postmortem::platform {

std::optional<std::string> unsupported_host_architecture() {
    USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;

    // IsWow64Process2 is the only API that reports the *native* machine rather
    // than the emulated one. Present since Windows 10 1511; if it is missing
    // the host predates ARM64 Windows entirely, so there is nothing to refuse.
    if (::IsWow64Process2(::GetCurrentProcess(), &process_machine, &native_machine) == FALSE) {
        return std::nullopt;
    }

    switch (native_machine) {
        case IMAGE_FILE_MACHINE_ARM64:
            return std::string(
                "this machine is ARM64; postmortem decodes x86 machine-check "
                "architecture registers and would report nonsense here (spec §3)");
        case IMAGE_FILE_MACHINE_ARMNT:
        case IMAGE_FILE_MACHINE_ARM:
            return std::string(
                "this machine is ARM32; postmortem decodes x86 machine-check "
                "architecture registers and would report nonsense here (spec §3)");
        default:
            break;
    }

    return std::nullopt;
}

}  // namespace postmortem::platform
