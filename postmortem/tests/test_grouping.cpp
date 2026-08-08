// The frequency tally behind `pm scan --group-by`.

#include <cstdint>
#include <string>
#include <vector>

#include "check.hpp"
#include "core/events/grouping.hpp"
#include "core/text/format.hpp"

using postmortem::events::GroupField;
using postmortem::events::group_records;
using postmortem::events::parse_group_fields;

namespace {

postmortem::events::WheaRecord make_record(std::int64_t time, unsigned apic, unsigned bank,
                                           std::uint64_t status, std::uint64_t address,
                                           unsigned event_id = 18) {
    postmortem::events::WheaRecord record;
    record.event.time = time;
    record.event.event_id = event_id;
    record.apic_id = apic;
    record.mca_bank = bank;
    record.mci_stat = status;
    record.mci_addr = address;
    record.error_type = 9;
    return record;
}

// The seven §7 vectors plus the shape of the real log: several APIC IDs,
// one bank, two distinct MCA_STATUS values.
std::vector<postmortem::events::WheaRecord> sample_records() {
    return {
        make_record(1000, 5, 5, 0xbea0000000000108ull, 0x1fff800b3409a9aull),
        make_record(2000, 11, 5, 0xbea0000000000108ull, 0x7fffc45c42feull),
        make_record(2000, 17, 5, 0xbea0000001000108ull, 0x7ff913a99f3bull),
        make_record(3000, 11, 5, 0xbea0000001000108ull, 0x7ff9a369eec3ull),
        make_record(4000, 11, 5, 0xbea0000001000108ull, 0x7ff9adb2715eull),
    };
}

std::vector<const postmortem::events::WheaRecord*> pointers(
    const std::vector<postmortem::events::WheaRecord>& records) {
    std::vector<const postmortem::events::WheaRecord*> out;
    for (const auto& record : records) out.push_back(&record);
    return out;
}

std::string utc(std::int64_t seconds) {
    return postmortem::text::format_utc(seconds);
}

}  // namespace

PM_TEST(grouping_parses_a_field_list) {
    const auto fields = parse_group_fields("event,bank,apic");
    PM_CHECK(fields.ok);
    PM_CHECK_EQ(fields.fields.size(), std::size_t{3});
    if (fields.fields.size() == 3) {
        PM_CHECK_EQ(fields.fields[0], GroupField::EventId);
        PM_CHECK_EQ(fields.fields[1], GroupField::Bank);
        PM_CHECK_EQ(fields.fields[2], GroupField::Apic);
    }

    // Whitespace around names is tolerated; an unknown name is named back.
    PM_CHECK(parse_group_fields(" apic , bank ").ok);
    const auto bad = parse_group_fields("apic,nonsense");
    PM_CHECK(!bad.ok);
    PM_CHECK(bad.error.find("nonsense") != std::string::npos);
    PM_CHECK(!parse_group_fields("").ok);
}

PM_TEST(grouping_counts_and_sorts_by_frequency) {
    const auto records = sample_records();
    const auto grouping = group_records(pointers(records), {GroupField::Apic},
                                        postmortem::cpu::Vendor::Amd, utc);

    PM_CHECK_EQ(grouping.total_records, std::size_t{5});
    PM_CHECK_EQ(grouping.rows.size(), std::size_t{3});
    if (grouping.rows.empty()) return;

    // APIC 11 appears three times and must lead.
    PM_CHECK_EQ(grouping.rows.front().count, std::size_t{3});
    PM_CHECK_EQ(grouping.rows.front().key.front(), std::string("11"));

    // Ties break on the key so the order is stable between runs.
    PM_CHECK_EQ(grouping.rows[1].count, std::size_t{1});
    PM_CHECK_EQ(grouping.rows[2].count, std::size_t{1});
    PM_CHECK(grouping.rows[1].key.front() < grouping.rows[2].key.front());
}

PM_TEST(grouping_tracks_first_and_last_seen) {
    const auto records = sample_records();
    const auto grouping = group_records(pointers(records), {GroupField::Apic},
                                        postmortem::cpu::Vendor::Amd, utc);
    PM_CHECK(!grouping.rows.empty());
    if (grouping.rows.empty()) return;

    // APIC 11 spans 2000..4000.
    PM_CHECK_EQ(grouping.rows.front().first_seen, std::int64_t{2000});
    PM_CHECK_EQ(grouping.rows.front().last_seen, std::int64_t{4000});
}

PM_TEST(grouping_by_several_fields_matches_group_object) {
    // The equivalent of Group-Object Id,Bank,Apic.
    const auto records = sample_records();
    const auto grouping =
        group_records(pointers(records), {GroupField::EventId, GroupField::Bank, GroupField::Apic},
                      postmortem::cpu::Vendor::Amd, utc);

    PM_CHECK_EQ(grouping.rows.size(), std::size_t{3});
    if (grouping.rows.empty()) return;
    PM_CHECK_EQ(grouping.rows.front().key.size(), std::size_t{3});
    PM_CHECK_EQ(grouping.rows.front().key[0], std::string("18"));
    PM_CHECK_EQ(grouping.rows.front().key[1], std::string("5"));
    PM_CHECK_EQ(grouping.rows.front().key[2], std::string("11"));
}

PM_TEST(grouping_by_status_separates_the_two_register_values) {
    const auto records = sample_records();
    const auto grouping = group_records(pointers(records), {GroupField::Status},
                                        postmortem::cpu::Vendor::Amd, utc);

    PM_CHECK_EQ(grouping.rows.size(), std::size_t{2});
    if (grouping.rows.size() != 2) return;
    // Three records carry the ...01000108 variant.
    PM_CHECK_EQ(grouping.rows.front().count, std::size_t{3});
    PM_CHECK_EQ(grouping.rows.front().key.front(), std::string("0xBEA0000001000108"));
}

PM_TEST(grouping_by_address_class_uses_the_mca_decoder) {
    const auto records = sample_records();
    const auto grouping = group_records(pointers(records), {GroupField::AddressClass},
                                        postmortem::cpu::Vendor::Amd, utc);

    // One kernel-mode address (0x1fff800b3409a9a) and four user-mode ones.
    PM_CHECK_EQ(grouping.rows.size(), std::size_t{2});
    if (grouping.rows.size() != 2) return;
    PM_CHECK_EQ(grouping.rows.front().key.front(), std::string("user VA"));
    PM_CHECK_EQ(grouping.rows.front().count, std::size_t{4});
    PM_CHECK_EQ(grouping.rows.back().key.front(), std::string("kernel VA"));
}

PM_TEST(grouping_by_error_code_extracts_the_low_sixteen_bits) {
    const auto records = sample_records();
    const auto grouping = group_records(pointers(records), {GroupField::ErrorCode},
                                        postmortem::cpu::Vendor::Amd, utc);

    // Every record is the same compound error code, so they collapse to one.
    PM_CHECK_EQ(grouping.rows.size(), std::size_t{1});
    if (grouping.rows.empty()) return;
    PM_CHECK_EQ(grouping.rows.front().key.front(), std::string("0x0108"));
    PM_CHECK_EQ(grouping.rows.front().count, std::size_t{5});
}

PM_TEST(grouping_day_and_hour_come_from_the_supplied_formatter) {
    std::vector<postmortem::events::WheaRecord> records;
    // 2026-06-26T20:38:52Z and an hour later.
    records.push_back(make_record(1782506332, 5, 5, 0xbea0000000000108ull, 0x7ffd4a38145eull));
    records.push_back(make_record(1782509932, 5, 5, 0xbea0000000000108ull, 0x7ffd4a38145eull));

    const auto by_day = group_records(pointers(records), {GroupField::Day},
                                      postmortem::cpu::Vendor::Amd, utc);
    PM_CHECK_EQ(by_day.rows.size(), std::size_t{1});
    if (!by_day.rows.empty()) {
        PM_CHECK_EQ(by_day.rows.front().key.front(), std::string("2026-06-26"));
    }

    const auto by_hour = group_records(pointers(records), {GroupField::Hour},
                                       postmortem::cpu::Vendor::Amd, utc);
    PM_CHECK_EQ(by_hour.rows.size(), std::size_t{2});
    if (by_hour.rows.size() == 2) {
        // Sorted by count then key, and both counts are 1.
        PM_CHECK_EQ(by_hour.rows[0].key.front(), std::string("20:00"));
        PM_CHECK_EQ(by_hour.rows[1].key.front(), std::string("21:00"));
    }
}

PM_TEST(grouping_handles_records_with_missing_fields) {
    // A record with no APIC or address must group under "-" rather than
    // being dropped, or the counts would not add up to the record total.
    postmortem::events::WheaRecord bare;
    bare.event.time = 500;
    bare.event.event_id = 47;

    std::vector<postmortem::events::WheaRecord> records = sample_records();
    records.push_back(bare);

    const auto grouping = group_records(pointers(records), {GroupField::Apic},
                                        postmortem::cpu::Vendor::Amd, utc);
    PM_CHECK_EQ(grouping.total_records, std::size_t{6});

    std::size_t counted = 0;
    for (const auto& row : grouping.rows) counted += row.count;
    PM_CHECK_EQ(counted, std::size_t{6});

    bool has_dash = false;
    for (const auto& row : grouping.rows) {
        if (row.key.front() == "-") has_dash = true;
    }
    PM_CHECK(has_dash);
}

PM_TEST(grouping_of_nothing_is_empty_not_broken) {
    const std::vector<const postmortem::events::WheaRecord*> none;
    const auto grouping =
        group_records(none, {GroupField::Apic}, postmortem::cpu::Vendor::Amd, utc);
    PM_CHECK_EQ(grouping.total_records, std::size_t{0});
    PM_CHECK(grouping.rows.empty());
}

PM_TEST(grouping_every_field_has_a_header_and_parses) {
    // A field added to the enum but not to the spec table would render as "?".
    for (const auto& spec : postmortem::events::group_field_specs()) {
        PM_CHECK(postmortem::events::parse_group_field(spec.name).has_value());
        PM_CHECK(!postmortem::events::group_field_header(spec.field).empty());
        PM_CHECK(postmortem::events::group_field_header(spec.field) != std::string_view("?"));
        PM_CHECK(!spec.description.empty());
    }
}
