#include "commands/decode.hpp"

#include <windows.h>

#include <cstdio>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "core/cper/record.hpp"
#include "core/input/values.hpp"
#include "core/json/writer.hpp"
#include "core/mca/registers.hpp"
#include "core/render/decode_view.hpp"
#include "core/text/format.hpp"
#include "platform/file.hpp"
#include "platform/screen.hpp"

namespace postmortem::commands {
namespace {

constexpr int kSuccess = 0;
constexpr int kFailure = 1;
constexpr int kUsage = 2;

void write_out(const std::string& text) {
    std::fwrite(text.data(), 1, text.size(), stdout);
}

void write_error(const std::string& message) {
    const std::string line = "pm: " + message + "\n";
    std::fwrite(line.data(), 1, line.size(), stderr);
}

struct VendorChoice {
    bool ok = true;
    cpu::Vendor vendor = cpu::Vendor::Unknown;
    std::string error;
};

// The vendor decides how MCA_ADDR and MCA_STATUS[56:53] are read, and there is
// nothing in a pasted register value to infer it from. Left unset it stays
// Unknown, and the decoder says so rather than assuming silently.
VendorChoice resolve_vendor(const cli::CommandLine& cmdline) {
    VendorChoice choice;
    const std::string* value = cmdline.option("vendor");
    if (value == nullptr) return choice;

    if (*value == "amd" || *value == "AMD") {
        choice.vendor = cpu::Vendor::Amd;
    } else if (*value == "intel" || *value == "Intel") {
        choice.vendor = cpu::Vendor::Intel;
    } else if (*value == "unknown") {
        choice.vendor = cpu::Vendor::Unknown;
    } else {
        choice.ok = false;
        choice.error = "unknown vendor '" + *value + "'; expected amd, intel or unknown";
    }
    return choice;
}

struct BlobSource {
    bool ok = false;
    std::vector<std::uint8_t> bytes;
    std::string origin;   // "hex", "base64", or "file <path>"
    std::string error;
};

// Accepts a hex or base64 string directly, or "@path" to read a file. A file
// is used verbatim when it already starts with the CPER signature, and
// otherwise re-parsed as text - people save both.
BlobSource load_blob(const std::string& value) {
    BlobSource source;

    if (!value.empty() && value.front() == '@') {
        const std::string path = value.substr(1);
        if (path.empty()) {
            source.error = "'@' must be followed by a file path";
            return source;
        }

        const platform::FileResult file = platform::read_file(path);
        if (!file.ok) {
            source.error = file.error;
            return source;
        }

        const bool looks_binary = file.bytes.size() >= 4 && file.bytes[0] == 'C' &&
                                  file.bytes[1] == 'P' && file.bytes[2] == 'E' &&
                                  file.bytes[3] == 'R';
        if (looks_binary) {
            source.ok = true;
            source.bytes = file.bytes;
            source.origin = "file " + path + " (raw binary)";
            return source;
        }

        const std::string text(reinterpret_cast<const char*>(file.bytes.data()),
                               file.bytes.size());
        const input::BlobResult parsed = input::parse_blob(text);
        if (!parsed.ok) {
            source.error = "'" + path + "' is neither a raw CPER record nor readable as " +
                           "hex or base64: " + parsed.error;
            return source;
        }
        source.ok = true;
        source.bytes = parsed.bytes;
        source.origin = "file " + path + " (" + parsed.format + ")";
        return source;
    }

    const input::BlobResult parsed = input::parse_blob(value);
    if (!parsed.ok) {
        source.error = parsed.error;
        return source;
    }
    source.ok = true;
    source.bytes = parsed.bytes;
    source.origin = parsed.format;
    return source;
}

struct RegisterValue {
    bool present = false;
    std::uint64_t value = 0;
    int base = 0;
};

// Parses one --mci-* option. Returns nullopt when the option was absent;
// reports and fails when it was present but unparseable.
bool read_register(const cli::CommandLine& cmdline, const char* name, RegisterValue& out) {
    const std::string* text = cmdline.option(name);
    if (text == nullptr) return true;

    const input::IntegerResult parsed = input::parse_u64(*text);
    if (!parsed.ok) {
        write_error(std::string("--") + name + ": " + parsed.error);
        return false;
    }
    out.present = true;
    out.value = parsed.value;
    out.base = parsed.base;
    return true;
}

// Spec §6: always show the raw value beside the interpretation. Reading a
// value in the wrong base would be the most basic way to be confidently wrong,
// so how it was read is stated whenever it was not written in hex.
std::string base_note(const RegisterValue& value) {
    if (value.base == 16) return {};
    return "read as base " + std::to_string(value.base) + " = " +
           text::to_hex(value.value, 16);
}

// The interactive walkthrough. Falls back to a single listing when stdout is
// not a console, so `pm decode --cper X --walk > walk.txt` is still useful.
int run_walk(std::span<const std::uint8_t> record,
             const std::vector<cper::FieldSpan>& fields, const text::Style& style) {
    platform::Screen screen;
    if (!screen.enter()) {
        write_out(render::walk_listing(record, fields, style));
        return kSuccess;
    }

    std::size_t step = 0;
    bool automatic = false;

    for (;;) {
        const platform::ScreenSize size = screen.size();
        screen.draw(render::walk_frame(record, fields, step, style, size.rows));

        int key = 0;
        if (automatic) {
            // Auto-advance, but stay responsive to a keypress.
            for (int slice = 0; slice < 6 && key == 0; ++slice) {
                key = platform::poll_key();
                ::Sleep(100);
            }
            if (key == 0) {
                if (step + 1 < fields.size()) {
                    ++step;
                } else {
                    automatic = false;
                }
                continue;
            }
        } else {
            while (key == 0) {
                key = platform::poll_key();
                ::Sleep(30);
            }
        }

        switch (key) {
            case 'q':
            case 'Q':
            case 3:            // Ctrl+C
                screen.leave();
                return kSuccess;
            case ' ':
            case 'n':
            case 'N':
                if (step + 1 < fields.size()) ++step;
                automatic = false;
                break;
            case 'p':
            case 'P':
                if (step > 0) --step;
                automatic = false;
                break;
            case 'a':
            case 'A':
                automatic = !automatic;
                break;
            case 'g':
                step = 0;
                break;
            case 'G':
                step = fields.empty() ? 0 : fields.size() - 1;
                break;
            default:
                break;
        }
    }
}

}  // namespace

int run_decode(const cli::CommandLine& cmdline, const text::Style& style) {
    if (!cmdline.operands.empty()) {
        write_error("'decode' takes options, not positional arguments; got '" +
                    cmdline.operands.front() + "'");
        return kUsage;
    }

    const VendorChoice vendor = resolve_vendor(cmdline);
    if (!vendor.ok) {
        write_error(vendor.error);
        return kUsage;
    }

    RegisterValue status;
    RegisterValue address;
    RegisterValue misc;
    if (!read_register(cmdline, "mci-stat", status)) return kUsage;
    if (!read_register(cmdline, "mci-addr", address)) return kUsage;
    if (!read_register(cmdline, "mci-misc", misc)) return kUsage;

    const std::string* cper_value = cmdline.option("cper");
    const bool any_register = status.present || address.present || misc.present;

    if (cper_value == nullptr && !any_register) {
        write_error("nothing to decode");
        write_out(
            "Give it something to work on:\n"
            "  pm decode --mci-stat 0xbea0000000000108 --mci-addr 0x1fff800c062b2a9\n"
            "  pm decode --cper <hex or base64>\n"
            "  pm decode --cper @record.bin\n"
            "\n"
            "Add --vendor amd or --vendor intel so the vendor-specific fields are read\n"
            "correctly; without it the AMD SMCA layout is assumed and said to be assumed.\n");
        return kUsage;
    }

    BlobSource blob;
    if (cper_value != nullptr) {
        blob = load_blob(*cper_value);
        if (!blob.ok) {
            write_error("--cper: " + blob.error);
            return kFailure;
        }
    }

    // MCA_MISC only means anything when MCA_STATUS.MiscV is set. If the status
    // register was supplied it settles the question; otherwise assume the user
    // would not have pasted MCA_MISC unless it was valid, and say so.
    bool misc_valid = true;
    if (status.present) {
        misc_valid = mca::decode_status(status.value, vendor.vendor).flags.misc_valid;
    }

    if (cmdline.global.json) {
        json::Writer writer(true);
        writer.begin_object();
        writer.key("tool").begin_object();
        writer.member("name", "postmortem");
        writer.member("command", "decode");
        writer.member("vendor", cpu::vendor_label(vendor.vendor));
        writer.end_object();

        if (status.present) {
            writer.key("mca_status");
            render::status_json(mca::decode_status(status.value, vendor.vendor), writer);
        }
        if (address.present) {
            writer.key("mca_addr");
            render::address_json(mca::decode_address(address.value, vendor.vendor), writer);
        }
        if (misc.present) {
            writer.key("mca_misc");
            render::misc_json(mca::decode_misc(misc.value, vendor.vendor, misc_valid), writer);
        }
        if (cper_value != nullptr) {
            writer.member("cper_source", blob.origin);
            writer.member_uint("cper_bytes", blob.bytes.size());
            writer.key("cper");
            render::record_json(cper::decode_record(blob.bytes), writer);
        }

        writer.end_object();
        write_out(writer.take() + "\n");
        return kSuccess;
    }

    std::string out;
    bool first = true;
    const auto separate = [&]() {
        if (!first) out += "\n";
        first = false;
    };

    if (status.present) {
        separate();
        const mca::StatusDecode decode = mca::decode_status(status.value, vendor.vendor);
        out += render::status_text(decode, style);
        if (const std::string note = base_note(status); !note.empty()) {
            out += text::bullet(note);
        }
    }

    if (address.present) {
        separate();
        const mca::AddressDecode decode = mca::decode_address(address.value, vendor.vendor);
        out += render::address_text(decode, style);
        if (const std::string note = base_note(address); !note.empty()) {
            out += text::bullet(note);
        }
        if (status.present) {
            const mca::StatusDecode status_decode =
                mca::decode_status(status.value, vendor.vendor);
            if (!status_decode.flags.address_valid) {
                out += text::bullet(
                    "MCA_STATUS.AddrV is clear, so this address is not valid and the reading "
                    "above should be disregarded");
            }
        }
    }

    if (misc.present) {
        separate();
        out += render::misc_text(mca::decode_misc(misc.value, vendor.vendor, misc_valid), style);
        if (const std::string note = base_note(misc); !note.empty()) {
            out += text::bullet(note);
        }
        if (!status.present) {
            out += text::bullet(
                "MCA_STATUS was not supplied, so it is not known whether MiscV was set; pass "
                "--mci-stat as well to have that checked");
        }
    }

    // --walk steps through the record field by field instead of printing the
    // finished decode. It is the same decode either way: the walk is driven by
    // spans the decoder records as it reads, not by a second layout table.
    if (cper_value != nullptr && cmdline.has_option("walk")) {
        cper::Trace trace;
        const cper::Record record = cper::decode_record_traced(blob.bytes, trace);
        if (!record.ok) {
            write_error("--cper: " + (record.errors.empty()
                                          ? std::string("this is not a CPER record")
                                          : record.errors.front()));
            return kFailure;
        }
        return run_walk(blob.bytes, trace.fields, style);
    }

    int exit_code = kSuccess;
    if (cper_value != nullptr) {
        separate();
        const cper::Record record = cper::decode_record(blob.bytes);
        out += render::record_text(record, style,
                                   render::Options{cmdline.global.verbose});
        out += '\n';
        out.append(style.dim);
        out += text::paragraph("Source: " + blob.origin + ", " +
                               std::to_string(blob.bytes.size()) + " bytes.");
        out.append(style.reset);
        if (!record.ok) exit_code = kFailure;
    }

    write_out(out);
    return exit_code;
}

}  // namespace postmortem::commands
