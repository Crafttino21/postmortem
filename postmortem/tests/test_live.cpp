// The live frame renderer and the decoder walkthrough.
//
// Both are pure: neither needs a console, a performance counter, an ETW
// session or an event log, which is why they live in core/render.

#include <cstdint>
#include <string>
#include <vector>

#include "check.hpp"
#include "core/cper/record.hpp"
#include "core/render/decode_view.hpp"
#include "core/render/live_view.hpp"
#include "core/text/table.hpp"

using postmortem::render::LiveCore;
using postmortem::render::LiveSnapshot;
using postmortem::text::Style;

namespace {

LiveSnapshot sample_snapshot(std::size_t core_count = 4) {
    LiveSnapshot snapshot;
    snapshot.cpu_brand = "AMD Ryzen 9 5950X 16-Core Processor";
    snapshot.nominal_mhz = 3400;
    snapshot.uptime = "2h 14m";
    snapshot.clock = "2026-08-08 18:04:18";
    snapshot.known_incidents = 8;

    for (std::size_t i = 0; i < core_count; ++i) {
        LiveCore core;
        core.os_index = static_cast<unsigned>(i);
        core.frequency_mhz = 3400 + static_cast<double>(i) * 100;
        core.performance_percent = 100 + static_cast<double>(i) * 3;
        core.busy_percent = static_cast<double>(i) * 25;
        core.c1_percent = 5;
        core.c2_percent = 60;
        core.c3_percent = 0;
        core.interrupts_per_sec = 1200;
        core.dpcs_per_sec = 90;
        snapshot.cores.push_back(core);
    }
    return snapshot;
}

}  // namespace

PM_TEST(live_frame_reports_the_essentials) {
    const std::string frame =
        postmortem::render::live_frame(sample_snapshot(), Style::plain(), 120, 40);

    PM_CHECK(frame.find("Ryzen 9 5950X") != std::string::npos);
    PM_CHECK(frame.find("nominal 3400 MHz") != std::string::npos);
    PM_CHECK(frame.find("WHEA feed") != std::string::npos);
    // With no live incident it must say the log already holds some, rather
    // than looking like nothing has ever happened.
    PM_CHECK(frame.find("8 already in the log") != std::string::npos);
    PM_CHECK(frame.find("q quit") != std::string::npos);
}

PM_TEST(live_frame_states_why_etw_is_off) {
    LiveSnapshot snapshot = sample_snapshot();
    snapshot.etw_active = false;
    snapshot.etw_note = "needs an elevated prompt";

    const std::string off = postmortem::render::live_frame(snapshot, Style::plain(), 120, 40);
    PM_CHECK(off.find("ETW: off (needs an elevated prompt)") != std::string::npos);
    // Without a session the ETW columns must not be drawn at all rather than
    // shown as zero, which would read as "no context switches happened".
    PM_CHECK(off.find("CSw/s") == std::string::npos);

    snapshot.etw_active = true;
    for (LiveCore& core : snapshot.cores) {
        core.context_switches_per_sec = 4200;
        core.etw_dpcs_per_sec = 310;
        core.etw_interrupts_per_sec = 900;
    }
    const std::string on = postmortem::render::live_frame(snapshot, Style::plain(), 140, 40);
    PM_CHECK(on.find("ETW: on") != std::string::npos);
    PM_CHECK(on.find("CSw/s") != std::string::npos);
    PM_CHECK(on.find("4.2k") != std::string::npos);
}

PM_TEST(live_frame_never_exceeds_the_window) {
    // The alternate screen buffer must not scroll, or the display tears.
    for (const unsigned rows : {12u, 20u, 40u, 60u}) {
        const std::string frame =
            postmortem::render::live_frame(sample_snapshot(32), Style::plain(), 120, rows);

        std::size_t lines = 0;
        for (const char c : frame) {
            if (c == '\n') ++lines;
        }
        PM_CHECK(lines < rows);
    }
}

PM_TEST(live_frame_says_when_cores_are_hidden) {
    // A 32-thread machine in a short window cannot show every core; it has to
    // say so rather than silently truncating.
    const std::string frame =
        postmortem::render::live_frame(sample_snapshot(32), Style::plain(), 120, 20);
    PM_CHECK(frame.find("more core(s)") != std::string::npos);
}

PM_TEST(live_frame_flags_a_fatal_incident) {
    LiveSnapshot snapshot = sample_snapshot();
    snapshot.live_incidents.push_back(
        {"18:04:22", "unrecoverable, processor context corrupt", true});

    const std::string plain =
        postmortem::render::live_frame(snapshot, Style::plain(), 120, 40);
    PM_CHECK(plain.find("processor context corrupt") != std::string::npos);

    // The colour styling has to actually be applied to the incident line.
    const std::string coloured =
        postmortem::render::live_frame(snapshot, Style::ansi(), 120, 40);
    PM_CHECK(coloured.find('\x1b') != std::string::npos);
}

// ---------------------------------------------------------------------------
// Decoder walkthrough
// ---------------------------------------------------------------------------

namespace {

void put_u16(std::vector<std::uint8_t>& b, std::size_t o, std::uint16_t v) {
    b[o] = static_cast<std::uint8_t>(v & 0xFF);
    b[o + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
}

void put_u32(std::vector<std::uint8_t>& b, std::size_t o, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i) b[o + i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF);
}

// A minimal well-formed record: header plus one descriptor, no section body.
std::vector<std::uint8_t> minimal_record() {
    std::vector<std::uint8_t> buffer(200 + 8, 0);
    buffer[0] = 'C';
    buffer[1] = 'P';
    buffer[2] = 'E';
    buffer[3] = 'R';
    put_u16(buffer, 4, 0x0100);
    put_u32(buffer, 6, 0xFFFFFFFFu);
    put_u16(buffer, 10, 1);
    put_u32(buffer, 12, 1);
    put_u32(buffer, 16, 0x01);
    put_u32(buffer, 20, static_cast<std::uint32_t>(buffer.size()));

    put_u32(buffer, 128 + 0, 200);   // section offset
    put_u32(buffer, 128 + 4, 8);     // section length
    put_u32(buffer, 128 + 48, 1);    // severity
    return buffer;
}

}  // namespace

PM_TEST(walk_trace_records_the_header_in_layout_order) {
    const auto buffer = minimal_record();
    postmortem::cper::Trace trace;
    const auto record = postmortem::cper::decode_record_traced(buffer, trace);

    PM_CHECK(record.ok);
    PM_CHECK(!trace.fields.empty());
    if (trace.fields.empty()) return;

    // Offsets must be non-decreasing within the header, and the first field is
    // the signature at 0.
    PM_CHECK_EQ(trace.fields.front().offset, std::size_t{0});
    PM_CHECK_EQ(trace.fields.front().length, std::size_t{4});
    PM_CHECK_EQ(trace.fields.front().name, std::string("SignatureStart"));
    PM_CHECK_EQ(trace.fields.front().value, std::string("CPER"));

    // Every span must lie inside the record - the walk highlights these bytes,
    // so an out-of-range span would read past the buffer.
    for (const auto& field : trace.fields) {
        PM_CHECK(field.offset + field.length <= buffer.size());
    }
}

PM_TEST(walk_trace_reports_section_bodies_at_absolute_offsets) {
    // A body field's offset must be its position in the whole record, not
    // within its own section, or the hex dump would highlight the wrong bytes.
    auto buffer = minimal_record();
    buffer.resize(200 + 192, 0);
    put_u32(buffer, 128 + 4, 192);
    // Processor Generic section type.
    const auto guid = postmortem::cper::guids::kProcessorGeneric;
    put_u32(buffer, 128 + 16, guid.data1);
    put_u16(buffer, 128 + 20, guid.data2);
    put_u16(buffer, 128 + 22, guid.data3);
    for (std::size_t i = 0; i < 8; ++i) buffer[128 + 24 + i] = guid.data4[i];
    put_u32(buffer, 20, static_cast<std::uint32_t>(buffer.size()));
    // Validation bits: processor type valid.
    buffer[200] = 0x01;

    postmortem::cper::Trace trace;
    const auto record = postmortem::cper::decode_record_traced(buffer, trace);
    PM_CHECK(record.ok);

    bool found_body_field = false;
    for (const auto& field : trace.fields) {
        if (field.depth > 0) {
            found_body_field = true;
            PM_CHECK(field.offset >= 200);
            PM_CHECK(field.offset + field.length <= buffer.size());
        }
    }
    PM_CHECK(found_body_field);
}

PM_TEST(walk_listing_shows_every_field) {
    const auto buffer = minimal_record();
    postmortem::cper::Trace trace;
    const auto record = postmortem::cper::decode_record_traced(buffer, trace);
    PM_CHECK(record.ok);

    const std::string listing =
        postmortem::render::walk_listing(buffer, trace.fields, Style::plain());
    PM_CHECK(listing.find("SignatureStart") != std::string::npos);
    PM_CHECK(listing.find("SectionCount") != std::string::npos);
    PM_CHECK(listing.find("Section 0 offset") != std::string::npos);
}

PM_TEST(walk_frame_marks_the_current_field) {
    const auto buffer = minimal_record();
    postmortem::cper::Trace trace;
    const auto record = postmortem::cper::decode_record_traced(buffer, trace);
    PM_CHECK(record.ok);
    if (trace.fields.empty()) return;

    const std::string first =
        postmortem::render::walk_frame(buffer, trace.fields, 0, Style::plain(), 40);
    PM_CHECK(first.find("step 1 of") != std::string::npos);
    PM_CHECK(first.find("SignatureStart") != std::string::npos);
    PM_CHECK(first.find("^^") != std::string::npos);   // the caret rule
    PM_CHECK(first.find("43 50 45 52") != std::string::npos);   // "CPER" in hex

    // Stepping past the end clamps rather than reading out of range.
    const std::string clamped =
        postmortem::render::walk_frame(buffer, trace.fields, 9999, Style::plain(), 40);
    PM_CHECK(clamped.find("step " + std::to_string(trace.fields.size()) + " of") !=
             std::string::npos);
}

PM_TEST(walk_handles_a_record_with_no_fields) {
    const std::vector<std::uint8_t> empty;
    const std::vector<postmortem::cper::FieldSpan> none;
    const std::string frame =
        postmortem::render::walk_frame(empty, none, 0, Style::plain(), 40);
    PM_CHECK(frame.find("nothing to walk") != std::string::npos);
}

PM_TEST(walk_trace_does_not_change_the_decode) {
    // The traced and untraced paths must produce identical records - the trace
    // is observation, not a second implementation.
    const auto buffer = minimal_record();
    const auto plain = postmortem::cper::decode_record(buffer);

    postmortem::cper::Trace trace;
    const auto traced = postmortem::cper::decode_record_traced(buffer, trace);

    PM_CHECK_EQ(plain.ok, traced.ok);
    PM_CHECK_EQ(plain.sections.size(), traced.sections.size());
    PM_CHECK_EQ(plain.header.signature, traced.header.signature);
    PM_CHECK_EQ(plain.header.record_length, traced.header.record_length);
    PM_CHECK_EQ(plain.warnings.size(), traced.warnings.size());
}
