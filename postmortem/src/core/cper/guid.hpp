// EFI_GUID handling for CPER records.
//
// A CPER record identifies every section, every FRU and every error-check
// structure by GUID, so getting the byte order right is a prerequisite for
// decoding anything at all. EFI_GUID stores Data1/Data2/Data3 little-endian
// and Data4 as eight raw bytes, which is why the textual form is not simply
// the bytes in order (UEFI spec, Appendix A).

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace postmortem::cper {

struct Guid {
    std::uint32_t data1 = 0;
    std::uint16_t data2 = 0;
    std::uint16_t data3 = 0;
    std::array<std::uint8_t, 8> data4{};

    friend bool operator==(const Guid& a, const Guid& b) {
        return a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 &&
               a.data4 == b.data4;
    }
};

// Reads the 16-byte on-disk form. Returns nullopt if fewer than 16 bytes are
// available - callers must not assume a GUID is present.
[[nodiscard]] std::optional<Guid> read_guid(std::span<const std::uint8_t> bytes);

// Canonical lowercase "9876ccad-47b4-4bdb-b65e-16f193c4f3db" form.
[[nodiscard]] std::string to_string(const Guid& guid);

// Parses the canonical form, with or without surrounding braces.
[[nodiscard]] std::optional<Guid> parse_guid(std::string_view text);

[[nodiscard]] bool is_null(const Guid& guid);

// The GUIDs spec §4.2 names, so the decoder can dispatch on them and the
// output can print a name instead of a bare GUID.
namespace guids {

// Section types (UEFI Appendix N).
extern const Guid kProcessorGeneric;   // 9876ccad-47b4-4bdb-b65e-16f193c4f3db
extern const Guid kIa32X64Processor;   // dc3ea0b0-a144-4797-b95b-53fa242b6e1d
extern const Guid kPlatformMemory;     // a5bc1114-6f64-4ede-b863-3e83ed7c83b1

// IA32/X64 error-check structure types.
extern const Guid kCacheCheck;         // a55701f5-e3ef-43de-ac72-249b573fad2c
extern const Guid kTlbCheck;           // fc06b535-5e1f-4562-9f25-0a3b9adb63c3
extern const Guid kBusCheck;           // 1cf3f8b3-c5b1-49a2-aa59-5eef92ffa63c
extern const Guid kMicroArchitecturalCheck;  // 48ab7f57-dc34-4f6c-a7d3-b0b5b0a74314

}  // namespace guids

// Human-readable name for a GUID this build knows, or an empty view.
// Deliberately conservative: an unrecognised GUID must be reported as
// unrecognised (spec §4.2), never guessed at.
[[nodiscard]] std::string_view known_name(const Guid& guid);

}  // namespace postmortem::cper
