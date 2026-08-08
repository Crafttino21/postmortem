// Thin, failure-tolerant registry reads.
//
// Every read returns std::nullopt rather than throwing: spec §2 requires the
// tool to degrade gracefully, and several of the keys read here (microcode
// revision in particular) are absent on some machines by design.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace postmortem::platform::registry {

enum class Hive {
    LocalMachine,
    CurrentUser,
};

[[nodiscard]] std::optional<std::string> read_string(Hive hive, const wchar_t* subkey,
                                                     const wchar_t* value);
[[nodiscard]] std::optional<std::uint32_t> read_dword(Hive hive, const wchar_t* subkey,
                                                      const wchar_t* value);
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_binary(Hive hive,
                                                                   const wchar_t* subkey,
                                                                   const wchar_t* value);

// Writes a REG_DWORD. Returns false rather than throwing; the caller reports
// the failure, and spec §2 requires the failure to be visible rather than
// leaving the user believing a mitigation was applied.
[[nodiscard]] bool write_dword(Hive hive, const wchar_t* subkey, const wchar_t* value,
                               std::uint32_t data);

}  // namespace postmortem::platform::registry
