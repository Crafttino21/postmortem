// UEFI Common Platform Error Record decoding (spec §4.2).
//
// The WHEA-Logger event's RawData field is a CPER record. This module turns
// that byte buffer into something a human can read, without ever trusting a
// length or offset that came out of it - see reader.hpp.
//
// Structure layouts cite the UEFI Specification, Appendix N ("Common Platform
// Error Record"):
//   Table N-1   Error Record Header          (128 bytes)
//   Table N-2   Section Descriptor           (72 bytes)
//   Table N-3   Error Record Header Timestamp (8 bytes, BCD)
//   N.2.4.1     Processor Generic section
//   N.2.4.2     IA32/X64 Processor Error section, and its check structures
//   N.2.5       Platform Memory Error section

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "core/cper/guid.hpp"
#include "core/cper/reader.hpp"
#include "core/cpu/signature.hpp"
#include "core/mca/registers.hpp"

namespace postmortem::cper {

// UEFI Table N-1, "Error Severity". The field is a UINT32 on the wire, and
// Unknown reuses the all-ones value, so the underlying type must be unsigned.
enum class Severity : std::uint32_t {
    Recoverable = 0,
    Fatal = 1,
    Corrected = 2,
    Informational = 3,
    Unknown = 0xFFFFFFFF,
};

[[nodiscard]] std::string_view severity_text(Severity severity);

// UEFI Table N-3. Every field is BCD-encoded, and firmware gets this wrong
// often enough that an implausible value is reported rather than normalised.
struct Timestamp {
    bool present = false;    // the header's validation bit was set
    bool precise = false;    // byte 3 bit 0
    bool plausible = false;  // all BCD digits decoded and the date is sane

    unsigned second = 0;
    unsigned minute = 0;
    unsigned hour = 0;
    unsigned day = 0;
    unsigned month = 0;
    unsigned year = 0;   // fully expanded, e.g. 2026

    std::uint64_t raw = 0;

    [[nodiscard]] std::string to_string() const;
};

struct RecordHeader {
    std::string signature;              // "CPER" when well-formed
    std::uint16_t revision = 0;
    std::uint32_t signature_end = 0;    // 0xFFFFFFFF when well-formed
    std::uint16_t section_count = 0;
    Severity severity = Severity::Unknown;
    std::uint32_t severity_raw = 0;
    std::uint32_t validation_bits = 0;
    std::uint32_t record_length = 0;
    Timestamp timestamp;

    Guid platform_id;
    Guid partition_id;
    Guid creator_id;
    Guid notification_type;

    std::uint64_t record_id = 0;
    std::uint32_t flags = 0;
    std::uint64_t persistence_info = 0;

    bool platform_id_valid = false;   // validation bit 0
    bool timestamp_valid = false;     // validation bit 1
    bool partition_id_valid = false;  // validation bit 2
};

// UEFI Table N-2.
struct SectionDescriptor {
    std::uint32_t offset = 0;
    std::uint32_t length = 0;
    std::uint16_t revision = 0;
    std::uint8_t validation_bits = 0;
    std::uint32_t flags = 0;
    Guid section_type;
    Guid fru_id;
    Severity severity = Severity::Unknown;
    std::uint32_t severity_raw = 0;
    std::string fru_text;

    bool fru_id_valid = false;    // validation bit 0
    bool fru_text_valid = false;  // validation bit 1

    std::vector<std::string> flag_names;
};

// --- Section bodies --------------------------------------------------------

// UEFI N.2.4.1.
struct ProcessorGenericSection {
    std::uint64_t validation_bits = 0;

    std::uint8_t processor_type = 0;
    std::uint8_t processor_isa = 0;
    std::uint8_t error_type = 0;
    std::uint8_t operation = 0;
    std::uint8_t flags = 0;
    std::uint8_t level = 0;

    // Spec §4.2: decode CPUVersion as CPUID leaf 1 EAX, including the
    // extended-family/extended-model arithmetic.
    std::uint64_t cpu_version = 0;
    bool signature_valid = false;
    cpu::Signature signature;

    std::string brand_string;   // the 128-byte field, when present

    std::uint64_t processor_id = 0;   // local APIC / processor ID
    std::uint64_t target_address = 0;
    std::uint64_t requestor_id = 0;
    std::uint64_t responder_id = 0;
    std::uint64_t instruction_ip = 0;

    std::string processor_type_text;
    std::string processor_isa_text;
    std::string error_type_text;
    std::string operation_text;
};

// The decoded contents of one 64-bit check-info word. Which rows are present
// depends on the check-structure GUID; validation bits decide which of them
// carry meaning, and rows whose validation bit is clear are omitted rather
// than shown as zero.
struct CheckInfo {
    std::string kind;                     // "Cache", "TLB", "Bus", ...
    std::uint64_t raw = 0;
    std::uint64_t validation_bits = 0;
    std::vector<mca::FieldRow> fields;
    std::vector<mca::BitRow> bits;
    std::vector<std::string> caveats;

    // Pulled out of the bit list so summarise() can reach the three flags that
    // decide the verdict without matching on display strings. Empty when the
    // corresponding validation bit was clear.
    std::optional<bool> processor_context_corrupt;
    std::optional<bool> uncorrected;
    std::optional<bool> overflow;
};

// UEFI Table N-9, Processor Error Info structure (64 bytes).
struct ProcessorErrorInfo {
    Guid check_type;
    std::string check_type_name;   // empty when unrecognised
    std::uint64_t validation_bits = 0;

    std::uint64_t check_info_raw = 0;
    std::optional<CheckInfo> check;

    std::optional<std::uint64_t> target_id;
    std::optional<std::uint64_t> requestor_id;
    std::optional<std::uint64_t> responder_id;
    std::optional<std::uint64_t> instruction_ip;
};

// UEFI N.2.4.2.
struct Ia32X64Section {
    std::uint64_t validation_bits = 0;
    bool apic_id_valid = false;
    bool cpuid_info_valid = false;

    std::uint64_t local_apic_id = 0;

    // The 48-byte CPUID dump; its first four bytes are leaf 1 EAX.
    std::vector<std::uint8_t> cpuid_info;
    bool signature_valid = false;
    cpu::Signature signature;

    // Spec §4.2: counts live in validation bits [7:2] and [13:8].
    unsigned declared_error_info_count = 0;
    unsigned declared_context_info_count = 0;

    std::vector<ProcessorErrorInfo> error_info;
    std::vector<std::string> caveats;
};

// UEFI N.2.5. Field presence is driven by the validation bitmap, so absent
// fields stay empty instead of reading as zero.
struct PlatformMemorySection {
    std::uint64_t validation_bits = 0;
    std::optional<std::uint64_t> error_status;
    std::optional<std::uint64_t> physical_address;
    std::optional<std::uint64_t> physical_address_mask;
    std::optional<unsigned> node;
    std::optional<unsigned> card;
    std::optional<unsigned> module;
    std::optional<unsigned> bank;
    std::optional<unsigned> device;
    std::optional<unsigned> row;
    std::optional<unsigned> column;
    std::optional<unsigned> bit_position;
    std::optional<unsigned> rank;
    std::optional<std::uint64_t> requestor_id;
    std::optional<std::uint64_t> responder_id;
    std::optional<std::uint64_t> target_id;
    std::optional<unsigned> memory_error_type;
    std::string memory_error_type_text;

    // SMBIOS Type 16/17 handles. Turning these into a DIMM label needs the
    // SMBIOS table, which is a platform concern and arrives with §4.8.
    std::optional<unsigned> card_handle;
    std::optional<unsigned> module_handle;

    std::vector<std::string> caveats;
};

struct Section {
    SectionDescriptor descriptor;
    std::string type_name;       // known_name(), or empty
    bool body_available = false; // the descriptor's extent was inside the record
    std::size_t body_offset = 0;
    std::size_t body_length = 0;

    std::optional<ProcessorGenericSection> processor_generic;
    std::optional<Ia32X64Section> ia32_x64;
    std::optional<PlatformMemorySection> platform_memory;

    // Spec §4.2: an unrecognised section GUID must not fail the decode. The
    // GUID, the length and a hex dump are emitted and parsing carries on.
    bool recognised = false;
    std::string hex_dump;

    std::vector<std::string> caveats;
};

struct Record {
    // False only when the buffer could not be treated as a CPER record at all
    // (no signature, or too short for a header). Anything recoverable is a
    // warning and leaves ok == true.
    bool ok = false;

    RecordHeader header;
    std::vector<Section> sections;

    std::vector<std::string> errors;
    std::vector<std::string> warnings;
};

[[nodiscard]] Record decode_record(std::span<const std::uint8_t> data);

// Same decode, but also records every field as it is consumed so
// `pm decode --walk` can step through the record byte by byte. The trace is
// empty when the record could not be decoded at all.
[[nodiscard]] Record decode_record_traced(std::span<const std::uint8_t> data, Trace& trace);

// Spec §6: "Lead with the verdict, then the evidence." This condenses a whole
// record into the one sentence that belongs on the first line.
struct RecordSummary {
    std::string headline;
    std::vector<std::string> notes;
};

[[nodiscard]] RecordSummary summarise(const Record& record);

// Decodes one section body given its type GUID. Exposed for tests and for
// milestone 3's `pm decode`, which can be handed a bare section.
void decode_section_body(Section& section, std::span<const std::uint8_t> body,
                         Trace* trace = nullptr);

}  // namespace postmortem::cper
