#include "commands/status.hpp"

#include <cstdio>
#include <string>

#include "core/json/writer.hpp"
#include "core/text/format.hpp"
#include "core/text/table.hpp"
#include "core/version.hpp"
#include "platform/cpu_info.hpp"
#include "platform/os_info.hpp"
#include "platform/smbios.hpp"

namespace postmortem::commands {
namespace {

using postmortem::text::to_hex;

constexpr const char* kUnknown = "unknown";

std::string or_unknown(const std::string& value) {
    return value.empty() ? kUnknown : value;
}

// "Family / Model / Stepping" the way both vendors' documentation writes it.
std::string format_signature(const cpu::Signature& sig) {
    return to_hex(sig.family, 2) + " / " + to_hex(sig.model, 2) + " / " + to_hex(sig.stepping);
}

std::string format_signature_note(const cpu::Signature& sig) {
    return "decimal " + std::to_string(sig.family) + " / " + std::to_string(sig.model) + " / " +
           std::to_string(sig.stepping) + ", CPUID.1 EAX = " + to_hex(sig.raw, 8);
}

std::string format_microcode(const platform::MicrocodeRevision& revision) {
    return to_hex(revision.revision, 8);
}

std::string format_microcode_note(const platform::MicrocodeRevision& revision) {
    // With a single DWORD in the registry the raw value *is* the revision, so
    // repeating it would be noise. The register pair is worth showing.
    std::string note;
    if (revision.raw_size_bytes > 4) {
        note = "raw " + to_hex(revision.raw, static_cast<int>(revision.raw_size_bytes) * 2);
    }
    if (!revision.interpretation_certain) {
        if (!note.empty()) note += ", ";
        note += "vendor unknown - half of the register pair guessed";
    }
    return note;
}

// "ASRock X570 Taichi" from the manufacturer/product pair, skipping whichever
// half the firmware left blank.
std::string join_nonempty(const std::string& first, const std::string& second) {
    if (first.empty()) return second;
    if (second.empty()) return first;
    return first + " " + second;
}

void render_cpu_text(const platform::CpuInfo& cpu, const text::Style& style, bool verbose,
                     std::string& out) {
    out += text::heading("CPU", style);

    text::KeyValueTable table;
    table.add("Brand", or_unknown(cpu.brand));

    std::string vendor = or_unknown(cpu.vendor_id);
    if (const std::string_view label = cpu::vendor_label(cpu.vendor); !label.empty()) {
        vendor += " (";
        vendor.append(label);
        vendor += ")";
    }
    table.add("Vendor", std::move(vendor));

    table.add("Family / Model / Step", format_signature(cpu.signature),
              format_signature_note(cpu.signature));

    if (cpu.topology_known) {
        table.add("Cores / Threads",
                  std::to_string(cpu.physical_cores) + " / " +
                      std::to_string(cpu.logical_processors));
        if (verbose) {
            table.add("NUMA nodes / groups",
                      std::to_string(cpu.numa_nodes) + " / " +
                          std::to_string(cpu.processor_groups));
        }
    } else {
        table.add("Cores / Threads", kUnknown, "GetLogicalProcessorInformationEx failed");
    }

    if (cpu.microcode.has_value()) {
        table.add("Microcode", format_microcode(*cpu.microcode),
                  format_microcode_note(*cpu.microcode));
    } else {
        table.add("Microcode", kUnknown, "not published by the loader on this machine");
    }
    if (verbose && cpu.microcode_previous.has_value()) {
        table.add("Microcode (previous)", format_microcode(*cpu.microcode_previous),
                  format_microcode_note(*cpu.microcode_previous));
    }

    if (cpu.nominal_mhz.has_value()) {
        table.add("Nominal clock", std::to_string(*cpu.nominal_mhz) + " MHz",
                  "firmware-reported base clock, not a live measurement");
    }

    if (cpu.hypervisor_present) {
        table.add("Hypervisor", "present",
                  cpu.hypervisor_vendor.empty() ? std::string("vendor leaf empty")
                                                : cpu.hypervisor_vendor);
    } else {
        table.add("Hypervisor", "not present");
    }

    out += table.render(style);
}

void render_firmware_text(const platform::FirmwareInfo& firmware, const text::Style& style,
                          std::string& out) {
    out += text::heading("Firmware", style);

    text::KeyValueTable table;
    if (!firmware.available) {
        table.add("SMBIOS", "unavailable", "GetSystemFirmwareTable(RSMB) returned nothing");
        out += table.render(style);
        return;
    }

    table.add("BIOS vendor", or_unknown(firmware.bios_vendor));
    table.add("BIOS version", or_unknown(firmware.bios_version));
    table.add("BIOS date", or_unknown(firmware.bios_release_date));
    if (firmware.bios_major_release.has_value()) {
        std::string revision = std::to_string(*firmware.bios_major_release);
        if (firmware.bios_minor_release.has_value()) {
            revision += "." + std::to_string(*firmware.bios_minor_release);
        }
        table.add("BIOS revision", std::move(revision));
    }

    const std::string board = join_nonempty(firmware.board_manufacturer, firmware.board_product);
    table.add("Board", or_unknown(join_nonempty(board, firmware.board_version)));

    const std::string system =
        join_nonempty(firmware.system_manufacturer, firmware.system_product);
    if (!system.empty()) table.add("System", system);

    table.add("SMBIOS", std::to_string(firmware.smbios_major) + "." +
                            std::to_string(firmware.smbios_minor));

    out += table.render(style);
}

void render_os_text(const platform::OsInfo& os, const text::Style& style, bool verbose,
                    std::string& out) {
    out += text::heading("Operating system", style);

    text::KeyValueTable table;
    std::string product = or_unknown(os.product_name);
    if (!os.display_version.empty()) product += " " + os.display_version;
    table.add("Product", std::move(product),
              os.edition_id.empty() ? std::string{} : "edition " + os.edition_id);

    table.add("Build", std::to_string(os.build) + "." + std::to_string(os.ubr),
              "version " + std::to_string(os.major) + "." + std::to_string(os.minor));

    if (verbose && !os.build_lab.empty()) table.add("Build lab", os.build_lab);

    if (os.install_date.has_value()) {
        table.add("Installed", platform::format_local_time(*os.install_date), "local time");
    } else {
        table.add("Installed", kUnknown);
    }

    table.add("Booted", platform::format_local_time(os.boot_time), "local time");
    table.add("Uptime", platform::format_duration(os.uptime_ms));

    out += table.render(style);
}

void render_json(const platform::CpuInfo& cpu, const platform::FirmwareInfo& firmware,
                 const platform::OsInfo& os, std::string& out) {
    json::Writer writer(true);
    writer.begin_object();

    writer.key("tool").begin_object();
    writer.member("name", "postmortem");
    writer.member("version", kVersion);
    writer.member("command", "status");
    writer.end_object();

    writer.key("cpu").begin_object();
    writer.member("brand", cpu.brand);
    writer.member("vendor_id", cpu.vendor_id);
    writer.member("vendor", cpu::vendor_label(cpu.vendor));
    writer.key("signature").begin_object();
    writer.member_hex("cpuid_1_eax", cpu.signature.raw, 8);
    writer.member_uint("family", cpu.signature.family);
    writer.member_uint("model", cpu.signature.model);
    writer.member_uint("stepping", cpu.signature.stepping);
    writer.member_uint("base_family", cpu.signature.base_family);
    writer.member_uint("base_model", cpu.signature.base_model);
    writer.member_uint("extended_family", cpu.signature.extended_family);
    writer.member_uint("extended_model", cpu.signature.extended_model);
    writer.end_object();

    writer.key("topology").begin_object();
    writer.member_bool("known", cpu.topology_known);
    writer.member_uint("physical_cores", cpu.physical_cores);
    writer.member_uint("logical_processors", cpu.logical_processors);
    writer.member_uint("numa_nodes", cpu.numa_nodes);
    writer.member_uint("processor_groups", cpu.processor_groups);
    writer.end_object();

    writer.key("microcode");
    if (cpu.microcode.has_value()) {
        writer.begin_object();
        writer.member_hex("revision", cpu.microcode->revision, 8);
        writer.member_hex("raw", cpu.microcode->raw,
                          static_cast<int>(cpu.microcode->raw_size_bytes) * 2);
        writer.member_uint("raw_size_bytes", cpu.microcode->raw_size_bytes);
        writer.member_bool("interpretation_certain", cpu.microcode->interpretation_certain);
        writer.end_object();
    } else {
        writer.value_null();
    }

    writer.key("hypervisor").begin_object();
    writer.member_bool("present", cpu.hypervisor_present);
    writer.member("vendor", cpu.hypervisor_vendor);
    writer.end_object();

    if (cpu.nominal_mhz.has_value()) {
        writer.member_uint("nominal_mhz", *cpu.nominal_mhz);
    } else {
        writer.member_null("nominal_mhz");
    }
    writer.end_object();   // cpu

    writer.key("firmware").begin_object();
    writer.member_bool("available", firmware.available);
    writer.member("smbios_version", std::to_string(firmware.smbios_major) + "." +
                                        std::to_string(firmware.smbios_minor));
    writer.member("bios_vendor", firmware.bios_vendor);
    writer.member("bios_version", firmware.bios_version);
    writer.member("bios_release_date", firmware.bios_release_date);
    if (firmware.bios_major_release.has_value()) {
        writer.member_uint("bios_major_release", *firmware.bios_major_release);
    } else {
        writer.member_null("bios_major_release");
    }
    if (firmware.bios_minor_release.has_value()) {
        writer.member_uint("bios_minor_release", *firmware.bios_minor_release);
    } else {
        writer.member_null("bios_minor_release");
    }
    writer.member("system_manufacturer", firmware.system_manufacturer);
    writer.member("system_product", firmware.system_product);
    writer.member("board_manufacturer", firmware.board_manufacturer);
    writer.member("board_product", firmware.board_product);
    writer.member("board_version", firmware.board_version);
    writer.end_object();

    writer.key("os").begin_object();
    writer.member("product_name", os.product_name);
    writer.member("display_version", os.display_version);
    writer.member("edition_id", os.edition_id);
    writer.member("build_lab", os.build_lab);
    writer.member_uint("major", os.major);
    writer.member_uint("minor", os.minor);
    writer.member_uint("build", os.build);
    writer.member_uint("ubr", os.ubr);
    if (os.install_date.has_value()) {
        writer.member_int("install_date_unix", *os.install_date);
    } else {
        writer.member_null("install_date_unix");
    }
    writer.member_int("boot_time_unix", os.boot_time);
    writer.member_uint("uptime_ms", os.uptime_ms);
    writer.member_int("collected_at_unix", os.now);
    writer.end_object();

    writer.end_object();

    out = writer.take();
    out += '\n';
}

}  // namespace

int run_status(const cli::CommandLine& cmdline, const text::Style& style) {
    const platform::CpuInfo cpu = platform::query_cpu_info();
    const platform::FirmwareInfo firmware = platform::query_firmware_info();
    const platform::OsInfo os = platform::query_os_info();

    std::string out;
    if (cmdline.global.json) {
        render_json(cpu, firmware, os, out);
    } else {
        render_cpu_text(cpu, style, cmdline.global.verbose, out);
        out += '\n';
        render_firmware_text(firmware, style, out);
        out += '\n';
        render_os_text(os, style, cmdline.global.verbose, out);

        // Spec §6: be explicit about what the tool does not know. The rest of
        // the §4.8 snapshot - crash-dump configuration, existing dumps, power
        // and idle state, VBS, DIMM inventory - is not collected yet.
        out += '\n';
        out.append(style.dim);
        out += "  Not collected yet: crash-dump configuration, existing dumps, power/idle\n";
        out += "  state, virtualization state, DIMM inventory (spec 4.8).";
        out.append(style.reset);
        out += '\n';
    }

    std::fwrite(out.data(), 1, out.size(), stdout);
    return 0;
}

}  // namespace postmortem::commands
