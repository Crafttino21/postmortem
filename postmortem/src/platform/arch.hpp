#pragma once

#include <optional>
#include <string>

namespace postmortem::platform {

// Spec §3: x64 only, refuse ARM64 cleanly.
//
// The configure-time gate in CMakeLists.txt cannot catch this case: an x64
// pm.exe runs quite happily under emulation on an ARM64 host, where the CPUID
// values it reads are synthesised by the emulator and the MCA decoding would
// be meaningless. Returns a message describing the problem, or nullopt when
// the host is supported.
[[nodiscard]] std::optional<std::string> unsupported_host_architecture();

}  // namespace postmortem::platform
