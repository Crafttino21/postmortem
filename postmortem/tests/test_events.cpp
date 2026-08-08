// Event ingestion, WHEA typing, incident clustering, timeline and analysis.
//
// All of this is driven from captured XML rather than a live event log, which
// is the point of keeping it in core/: the ingestion path is testable on a
// machine that has never crashed.

#include <cstdint>
#include <string>
#include <vector>

#include "check.hpp"
#include "core/events/analysis.hpp"
#include "core/events/event.hpp"
#include "core/events/crash_timeline.hpp"
#include "core/events/whea.hpp"
#include "core/xml/parse.hpp"

namespace {

// A WHEA-Logger event ID 18, in the shape EvtRender produces.
std::string whea_xml(const char* time, unsigned apic, const char* mci_stat,
                     const char* mci_addr, std::uint64_t record_id) {
    std::string out =
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System>"
        "<Provider Name='Microsoft-Windows-WHEA-Logger' "
        "Guid='{c26c4f3c-3f66-4e99-8f8a-39405cfed220}'/>"
        "<EventID>18</EventID><Version>0</Version><Level>1</Level><Task>0</Task>"
        "<Channel>System</Channel><Computer>TESTBOX</Computer>"
        "<EventRecordID>";
    out += std::to_string(record_id);
    out += "</EventRecordID><TimeCreated SystemTime='";
    out += time;
    out += "'/></System><EventData>"
           "<Data Name='ErrorSource'>3</Data>"
           "<Data Name='ApicId'>";
    out += std::to_string(apic);
    out += "</Data><Data Name='MCABank'>5</Data>"
           "<Data Name='MciStat'>";
    out += mci_stat;
    out += "</Data><Data Name='MciAddr'>";
    out += mci_addr;
    out += "</Data><Data Name='MciMisc'>0xd0130fff00000000</Data>"
           "<Data Name='ErrorType'>9</Data>"
           "<Data Name='TransactionType'>2</Data>"
           "<Data Name='RawData'>43504552</Data>"
           "</EventData></Event>";
    return out;
}

std::string simple_event(const char* provider, unsigned event_id, const char* time,
                         const std::string& extra_data = {}) {
    std::string out = "<Event><System><Provider Name='";
    out += provider;
    out += "'/><EventID>";
    out += std::to_string(event_id);
    out += "</EventID><TimeCreated SystemTime='";
    out += time;
    out += "'/></System><EventData>";
    out += extra_data;
    out += "</EventData></Event>";
    return out;
}

postmortem::events::Event parse_event(const std::string& xml) {
    const auto event = postmortem::events::from_xml_text(xml);
    return event.has_value() ? *event : postmortem::events::Event{};
}

}  // namespace

// ---------------------------------------------------------------------------
// XML
// ---------------------------------------------------------------------------

PM_TEST(xml_parses_elements_attributes_and_text) {
    const auto document = postmortem::xml::parse(
        "<?xml version='1.0'?><root a='1' b=\"two\"><child>text</child><empty/></root>");
    PM_CHECK(document.ok);
    if (!document.ok) return;

    PM_CHECK_EQ(document.root.name, std::string("root"));
    PM_CHECK(document.root.attribute("a") != nullptr);
    if (document.root.attribute("a") != nullptr) {
        PM_CHECK_EQ(*document.root.attribute("a"), std::string("1"));
    }
    PM_CHECK_EQ(*document.root.attribute("b"), std::string("two"));

    const auto* child = document.root.child("child");
    PM_CHECK(child != nullptr);
    if (child != nullptr) PM_CHECK_EQ(child->text, std::string("text"));
    PM_CHECK(document.root.child("empty") != nullptr);
    PM_CHECK(document.root.child("absent") == nullptr);
}

PM_TEST(xml_strips_namespace_prefixes) {
    // Event XML uses prefixes inconsistently between providers; stripping them
    // means lookups do not have to care.
    const auto document = postmortem::xml::parse("<e:Event><e:System/></e:Event>");
    PM_CHECK(document.ok);
    if (document.ok) {
        PM_CHECK_EQ(document.root.name, std::string("Event"));
        PM_CHECK(document.root.child("System") != nullptr);
    }
}

PM_TEST(xml_decodes_entities) {
    using postmortem::xml::decode_entities;
    PM_CHECK_EQ(decode_entities("a&lt;b&gt;c"), std::string("a<b>c"));
    PM_CHECK_EQ(decode_entities("&amp;&quot;&apos;"), std::string("&\"'"));
    PM_CHECK_EQ(decode_entities("&#65;&#x42;"), std::string("AB"));
    // An unknown entity is kept verbatim rather than dropped: silently losing
    // characters from a field the user will read is worse than leaving them.
    PM_CHECK_EQ(decode_entities("&nosuch;"), std::string("&nosuch;"));
    PM_CHECK_EQ(decode_entities("100% & rising"), std::string("100% & rising"));
}

PM_TEST(xml_finds_nested_paths) {
    const auto document =
        postmortem::xml::parse("<Event><System><Provider Name='X'/></System></Event>");
    PM_CHECK(document.ok);
    if (!document.ok) return;

    const auto* provider = document.root.find("System/Provider");
    PM_CHECK(provider != nullptr);
    if (provider != nullptr) PM_CHECK_EQ(*provider->attribute("Name"), std::string("X"));
    PM_CHECK(document.root.find("System/Missing") == nullptr);
}

PM_TEST(xml_rejects_malformed_input) {
    PM_CHECK(!postmortem::xml::parse("").ok);
    PM_CHECK(!postmortem::xml::parse("not xml").ok);
    PM_CHECK(!postmortem::xml::parse("<a><b></a>").ok);   // mismatched close
    PM_CHECK(!postmortem::xml::parse("<a attr>").ok);     // attribute with no value
    PM_CHECK(!postmortem::xml::parse("<a>").ok);          // never closed

    // Deep nesting must not exhaust the stack.
    std::string deep;
    for (int i = 0; i < 500; ++i) deep += "<n>";
    PM_CHECK(!postmortem::xml::parse(deep).ok);
}

// ---------------------------------------------------------------------------
// Event and WHEA typing
// ---------------------------------------------------------------------------

PM_TEST(events_reads_the_system_block) {
    const auto event = parse_event(whea_xml("2026-06-26T20:38:52.1234567Z", 11,
                                            "0xbea0000000000108", "0x1fff800c062b2a9", 4242));
    PM_CHECK_EQ(event.provider, std::string("Microsoft-Windows-WHEA-Logger"));
    PM_CHECK_EQ(event.event_id, 18u);
    PM_CHECK_EQ(event.record_id, std::uint64_t{4242});
    PM_CHECK_EQ(event.computer, std::string("TESTBOX"));
    PM_CHECK(postmortem::events::is_whea_event(event));

    // 2026-06-26T20:38:52Z.
    PM_CHECK_EQ(event.time, std::int64_t{1782506332});
    PM_CHECK_EQ(event.time_nanoseconds, 123456700u);
}

PM_TEST(events_types_the_whea_fields) {
    const auto record = postmortem::events::from_event(parse_event(
        whea_xml("2026-06-26T20:38:52Z", 11, "0xbea0000000000108", "0x1fff800c062b2a9", 1)));

    PM_CHECK(record.apic_id.has_value());
    if (record.apic_id.has_value()) PM_CHECK_EQ(*record.apic_id, 11u);
    PM_CHECK_EQ(*record.mca_bank, 5u);
    PM_CHECK_EQ(*record.mci_stat, 0xbea0000000000108ull);
    PM_CHECK_EQ(*record.mci_addr, 0x1fff800c062b2a9ull);
    PM_CHECK_EQ(*record.error_type, 9u);
    PM_CHECK_EQ(*record.transaction_type, 2u);

    // RawData "43504552" is the ASCII for CPER, decoded from hex.
    PM_CHECK_EQ(record.raw_data.size(), std::size_t{4});
    PM_CHECK_EQ(record.raw_data_format, std::string("hex"));

    // The status bits are readable without a full decode.
    PM_CHECK(record.is_uncorrected());
    PM_CHECK(record.is_context_corrupt());
}

PM_TEST(events_survives_an_event_with_no_eventdata) {
    const auto event = parse_event("<Event><System><Provider Name='X'/><EventID>1</EventID>"
                                   "</System></Event>");
    const auto record = postmortem::events::from_event(event);
    PM_CHECK(!record.apic_id.has_value());
    PM_CHECK(!record.mci_stat.has_value());
    PM_CHECK(record.raw_data.empty());
    PM_CHECK(!record.is_uncorrected());
}

// ---------------------------------------------------------------------------
// Incident clustering (spec §4.5)
// ---------------------------------------------------------------------------

PM_TEST(events_clusters_a_broadcast_machine_check_into_one_incident) {
    // "uncorrectable MCEs are broadcast to all cores, producing one record per
    // processor - the tool must recognise this and present it as one incident
    // with N reporting cores, not N incidents."
    std::vector<postmortem::events::WheaRecord> records;
    for (unsigned apic : {5u, 11u, 17u}) {
        records.push_back(postmortem::events::from_event(parse_event(
            whea_xml("2026-06-26T20:38:52Z", apic, "0xbea0000000000108", "0x7ffd4a38145e",
                     apic))));
    }

    const auto incidents = postmortem::events::cluster(std::move(records));
    PM_CHECK_EQ(incidents.size(), std::size_t{1});
    if (incidents.empty()) return;

    PM_CHECK_EQ(incidents.front().records.size(), std::size_t{3});
    PM_CHECK_EQ(incidents.front().apic_ids.size(), std::size_t{3});
    PM_CHECK_EQ(incidents.front().banks.size(), std::size_t{1});
    PM_CHECK(incidents.front().uncorrected);
    PM_CHECK(incidents.front().context_corrupt);
    PM_CHECK(incidents.front().headline().find("3 cores") != std::string::npos);
}

PM_TEST(events_keeps_distant_records_as_separate_incidents) {
    std::vector<postmortem::events::WheaRecord> records;
    records.push_back(postmortem::events::from_event(parse_event(
        whea_xml("2026-06-26T20:38:52Z", 5, "0xbea0000000000108", "0x7ffd4a38145e", 1))));
    records.push_back(postmortem::events::from_event(parse_event(
        whea_xml("2026-07-04T18:22:54Z", 10, "0xbea0000000000108", "0x7ffd4a38145e", 2))));

    const auto incidents = postmortem::events::cluster(std::move(records));
    PM_CHECK_EQ(incidents.size(), std::size_t{2});
}

PM_TEST(events_marks_records_harvested_after_a_boot) {
    // Spec §4.5: "MCA banks are sticky across warm reset, so a WHEA record
    // timestamped seconds after boot usually belongs to the previous session's
    // crash."
    std::vector<postmortem::events::WheaRecord> records;
    records.push_back(postmortem::events::from_event(parse_event(
        whea_xml("2026-06-26T20:38:52Z", 5, "0xbea0000000000108", "0x7ffd4a38145e", 1))));
    auto incidents = postmortem::events::cluster(std::move(records));

    // Boot 19 seconds earlier.
    const std::int64_t boot = incidents.front().time - 19;
    postmortem::events::mark_post_boot_harvest(incidents, {boot});

    PM_CHECK(incidents.front().post_boot_harvest);
    PM_CHECK_EQ(incidents.front().seconds_after_boot, std::int64_t{19});

    // An incident well into the session is not a harvest.
    auto later = incidents;
    later.front().post_boot_harvest = false;
    postmortem::events::mark_post_boot_harvest(later, {later.front().time - 7200});
    PM_CHECK(!later.front().post_boot_harvest);
}

// ---------------------------------------------------------------------------
// Timeline (spec §4.5)
// ---------------------------------------------------------------------------

PM_TEST(timeline_reads_bugcheck_code_zero_as_the_signature_case) {
    std::vector<postmortem::events::Event> events;
    events.push_back(parse_event(simple_event("Microsoft-Windows-Kernel-Boot", 20,
                                              "2026-06-26T20:38:33Z")));
    events.push_back(parse_event(simple_event(
        "Microsoft-Windows-Kernel-Power", 41, "2026-06-26T20:38:36Z",
        "<Data Name='BugcheckCode'>0</Data><Data Name='WHEABootErrorCount'>1</Data>")));

    const auto timeline = postmortem::events::build_timeline(events, {});
    PM_CHECK(timeline.headline.find("1 unexpected shutdown") != std::string::npos);
    PM_CHECK(timeline.headline.find("1 with no bugcheck code") != std::string::npos);

    bool explained = false;
    bool counted_boot_errors = false;
    for (const auto& entry : timeline.entries) {
        for (const std::string& note : entry.notes) {
            if (note.find("never got as far as a bugcheck") != std::string::npos) {
                explained = true;
            }
            if (note.find("WHEABootErrorCount is 1") != std::string::npos) {
                counted_boot_errors = true;
            }
        }
    }
    PM_CHECK(explained);
    PM_CHECK(counted_boot_errors);
}

PM_TEST(timeline_distinguishes_a_real_bugcheck) {
    std::vector<postmortem::events::Event> events;
    events.push_back(parse_event(simple_event("Microsoft-Windows-Kernel-Power", 41,
                                              "2026-06-26T20:38:36Z",
                                              "<Data Name='BugcheckCode'>292</Data>")));
    const auto timeline = postmortem::events::build_timeline(events, {});
    PM_CHECK(timeline.headline.find("0 with no bugcheck code") != std::string::npos);
    PM_CHECK(timeline.headline.find("1 with one") != std::string::npos);
}

PM_TEST(timeline_collapses_per_processor_noise) {
    // Kernel-Processor-Power 55 fires once per logical processor.
    std::vector<postmortem::events::Event> events;
    for (int i = 0; i < 32; ++i) {
        events.push_back(parse_event(simple_event(
            "Microsoft-Windows-Kernel-Processor-Power", 55, "2026-06-26T20:38:36Z")));
    }
    const auto timeline = postmortem::events::build_timeline(events, {});

    PM_CHECK_EQ(timeline.entries.size(), std::size_t{1});
    if (!timeline.entries.empty()) PM_CHECK_EQ(timeline.entries.front().repeats, std::size_t{32});
}

PM_TEST(timeline_groups_entries_into_boot_sessions) {
    std::vector<postmortem::events::Event> events;
    events.push_back(parse_event(simple_event("Microsoft-Windows-Kernel-General", 12,
                                              "2026-06-26T10:00:00Z")));
    events.push_back(parse_event(simple_event("Microsoft-Windows-Kernel-General", 13,
                                              "2026-06-26T12:00:00Z")));
    events.push_back(parse_event(simple_event("Microsoft-Windows-Kernel-General", 12,
                                              "2026-06-26T14:00:00Z")));
    events.push_back(parse_event(simple_event("Microsoft-Windows-Kernel-Power", 41,
                                              "2026-06-26T16:00:00Z",
                                              "<Data Name='BugcheckCode'>0</Data>")));

    const auto timeline = postmortem::events::build_timeline(events, {});
    PM_CHECK_EQ(timeline.sessions.size(), std::size_t{2});
    if (timeline.sessions.size() == 2) {
        PM_CHECK(!timeline.sessions[0].ended_unexpectedly);
        PM_CHECK(timeline.sessions[1].ended_unexpectedly);
    }
}

// ---------------------------------------------------------------------------
// Analysis (spec §4.6)
// ---------------------------------------------------------------------------

namespace {

std::vector<postmortem::events::Incident> incidents_at(const std::vector<std::int64_t>& times,
                                                       unsigned apic = 5) {
    std::vector<postmortem::events::Incident> incidents;
    for (const std::int64_t time : times) {
        postmortem::events::Incident incident;
        incident.time = time;
        incident.last_time = time;
        incident.apic_ids = {apic};
        incident.banks = {5};
        incident.uncorrected = true;
        incident.context_corrupt = true;

        postmortem::events::WheaRecord record;
        record.mci_stat = 0xbea0000000000108ull;
        record.mci_addr = 0x7ffd4a38145eull + static_cast<std::uint64_t>(time);
        incident.records.push_back(record);
        incidents.push_back(std::move(incident));
    }
    return incidents;
}

}  // namespace

PM_TEST(analysis_reports_no_data_as_a_result_rather_than_a_blank) {
    postmortem::events::AnalysisInput input;
    const auto analysis = postmortem::events::analyse(input);
    PM_CHECK_EQ(analysis.incident_count, std::size_t{0});
    PM_CHECK(analysis.verdict.find("not reporting a machine-check") != std::string::npos);
}

PM_TEST(analysis_detects_a_flat_rate) {
    // Seven incidents, evenly spaced ten days apart.
    std::vector<std::int64_t> times;
    for (int i = 0; i < 7; ++i) times.push_back(1'700'000'000LL + i * 10 * 86400);

    postmortem::events::AnalysisInput input;
    input.incidents = incidents_at(times);
    const auto analysis = postmortem::events::analyse(input);

    PM_CHECK_EQ(analysis.trend, postmortem::events::RateTrend::Flat);
    PM_CHECK_EQ(*analysis.median_interval, std::int64_t{10 * 86400});
    PM_CHECK(analysis.verdict.find("fixed marginality") != std::string::npos);
}

PM_TEST(analysis_detects_an_accelerating_rate) {
    // Gaps of 30, 30, 30, 5, 5, 5 days.
    std::vector<std::int64_t> times{0};
    for (const int days : {30, 30, 30, 5, 5, 5}) {
        times.push_back(times.back() + days * 86400LL);
    }

    postmortem::events::AnalysisInput input;
    input.incidents = incidents_at(times);
    const auto analysis = postmortem::events::analyse(input);

    PM_CHECK_EQ(analysis.trend, postmortem::events::RateTrend::Accelerating);
    PM_CHECK(analysis.verdict.find("degradation") != std::string::npos);
}

PM_TEST(analysis_refuses_to_judge_a_trend_from_too_few_points) {
    postmortem::events::AnalysisInput input;
    input.incidents = incidents_at({0, 86400, 200000});
    const auto analysis = postmortem::events::analyse(input);

    PM_CHECK_EQ(analysis.trend, postmortem::events::RateTrend::TooFewSamples);
    bool admitted = false;
    for (const auto& finding : analysis.findings) {
        if (finding.claim.find("too few incidents") != std::string::npos) admitted = true;
    }
    PM_CHECK(admitted);
}

PM_TEST(analysis_counts_per_core_and_per_bank) {
    postmortem::events::AnalysisInput input;
    input.incidents = incidents_at({0, 86400, 172800}, 11);
    input.incidents[2].apic_ids = {7};

    const auto analysis = postmortem::events::analyse(input);
    PM_CHECK_EQ(analysis.per_apic.size(), std::size_t{2});
    // Sorted by count, so APIC 11 with two incidents comes first.
    PM_CHECK_EQ(analysis.per_apic.front().value, 11u);
    PM_CHECK_EQ(analysis.per_apic.front().count, std::size_t{2});
    PM_CHECK_EQ(analysis.per_bank.size(), std::size_t{1});
}

PM_TEST(analysis_flags_clustered_addresses) {
    postmortem::events::AnalysisInput input;
    input.incidents = incidents_at({0, 86400, 172800, 259200});
    // Force every record onto the same page.
    for (auto& incident : input.incidents) {
        incident.records.front().mci_addr = 0x7ffd4a380000ull;
    }

    const auto analysis = postmortem::events::analyse(input);
    PM_CHECK(analysis.addresses.measurable);
    PM_CHECK(analysis.addresses.clustered);
    PM_CHECK_EQ(analysis.addresses.distinct_pages, std::size_t{1});
}
