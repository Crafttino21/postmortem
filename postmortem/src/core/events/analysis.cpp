#include "core/events/analysis.hpp"

#include <algorithm>
#include <map>
#include <numeric>

#include "core/text/format.hpp"

namespace postmortem::events {
namespace {

std::vector<CountedValue> tally(const std::map<unsigned, std::size_t>& counts) {
    std::vector<CountedValue> result;
    result.reserve(counts.size());
    for (const auto& [value, count] : counts) result.push_back(CountedValue{value, count});
    std::sort(result.begin(), result.end(), [](const CountedValue& a, const CountedValue& b) {
        if (a.count != b.count) return a.count > b.count;
        return a.value < b.value;
    });
    return result;
}

std::int64_t median(std::vector<std::int64_t> values) {
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const std::size_t middle = values.size() / 2;
    if (values.size() % 2 == 1) return values[middle];
    return (values[middle - 1] + values[middle]) / 2;
}

// Compares the first half of the inter-arrival intervals with the second half.
// An accelerating failure rate means the later gaps are shorter.
RateTrend classify_trend(const std::vector<std::int64_t>& intervals) {
    // Four intervals means five incidents; below that the comparison is noise.
    if (intervals.size() < 4) return RateTrend::TooFewSamples;

    const std::size_t half = intervals.size() / 2;
    const std::vector<std::int64_t> early(intervals.begin(), intervals.begin() + half);
    const std::vector<std::int64_t> late(intervals.begin() + half, intervals.end());

    const std::int64_t early_median = median(early);
    const std::int64_t late_median = median(late);
    if (early_median == 0 || late_median == 0) return RateTrend::TooFewSamples;

    // A 25% shift is the threshold; anything smaller is not distinguishable
    // from ordinary scatter at these sample sizes.
    if (late_median * 4 < early_median * 3) return RateTrend::Accelerating;
    if (late_median * 3 > early_median * 4) return RateTrend::Decelerating;
    return RateTrend::Flat;
}

AddressClustering analyse_addresses(const std::vector<Incident>& incidents) {
    AddressClustering clustering;

    std::map<std::uint64_t, std::size_t> pages;
    for (const Incident& incident : incidents) {
        for (const WheaRecord& record : incident.records) {
            if (!record.mci_addr.has_value()) continue;
            // Use the SMCA address bits, which is what carries a location.
            const std::uint64_t address = *record.mci_addr & 0x00FFFFFFFFFFFFFFull;
            if (address == 0) continue;
            ++clustering.sample_count;
            ++pages[address >> 12];
        }
    }

    if (clustering.sample_count < 3) return clustering;

    clustering.measurable = true;
    clustering.distinct_pages = pages.size();
    for (const auto& [page, count] : pages) {
        (void)page;
        clustering.largest_page_group = std::max(clustering.largest_page_group, count);
    }

    // Clustering means a defective physical structure; scatter means timing or
    // voltage marginality (spec §4.6).
    clustering.clustered = clustering.distinct_pages * 2 <= clustering.sample_count;
    return clustering;
}

}  // namespace

std::string_view confidence_text(Confidence confidence) {
    switch (confidence) {
        case Confidence::Weak:     return "weak";
        case Confidence::Moderate: return "moderate";
        case Confidence::Strong:   return "strong";
    }
    return "unknown";
}

std::string_view rate_trend_text(RateTrend trend) {
    switch (trend) {
        case RateTrend::TooFewSamples: return "too few incidents to say";
        case RateTrend::Flat:          return "flat";
        case RateTrend::Accelerating:  return "accelerating";
        case RateTrend::Decelerating:  return "decelerating";
    }
    return "unknown";
}

Analysis analyse(const AnalysisInput& input) {
    Analysis analysis;
    analysis.incident_count = input.incidents.size();
    analysis.install_date = input.install_date;

    if (input.incidents.empty()) {
        analysis.verdict =
            "No WHEA records in the selected range, so there is nothing to trend. That is a "
            "result in itself: whatever is resetting this machine is not reporting a "
            "machine-check exception to Windows.";
        return analysis;
    }

    std::map<unsigned, std::size_t> apic_counts;
    std::map<unsigned, std::size_t> bank_counts;

    for (const Incident& incident : input.incidents) {
        analysis.record_count += incident.records.size();
        for (const unsigned apic : incident.apic_ids) ++apic_counts[apic];
        for (const unsigned bank : incident.banks) ++bank_counts[bank];
        if (input.local_hour) {
            const unsigned hour = input.local_hour(incident.time);
            if (hour < 24) ++analysis.by_hour[hour];
        }
    }

    analysis.per_apic = tally(apic_counts);
    analysis.per_bank = tally(bank_counts);
    analysis.first_seen = input.incidents.front().time;
    analysis.last_seen = input.incidents.back().time;

    for (std::size_t i = 1; i < input.incidents.size(); ++i) {
        analysis.intervals.push_back(input.incidents[i].time - input.incidents[i - 1].time);
    }
    if (!analysis.intervals.empty()) {
        analysis.median_interval = median(analysis.intervals);
        analysis.mean_interval =
            std::accumulate(analysis.intervals.begin(), analysis.intervals.end(),
                            std::int64_t{0}) /
            static_cast<std::int64_t>(analysis.intervals.size());
    }
    analysis.trend = classify_trend(analysis.intervals);
    analysis.addresses = analyse_addresses(input.incidents);

    // --- Findings ----------------------------------------------------------

    std::size_t fatal = 0;
    for (const Incident& incident : input.incidents) {
        if (incident.uncorrected && incident.context_corrupt) ++fatal;
    }
    if (fatal > 0) {
        analysis.findings.push_back(Finding{
            std::to_string(fatal) +
                " incident(s) are uncorrected with processor context corrupt",
            "UC=1 with PCC=1 means the CPU could not continue and reset itself. That is why "
            "these crashes leave no bugcheck and no dump - by the time Windows could have "
            "written one, the processor had already restarted.",
            Confidence::Strong});
    }

    if (analysis.per_bank.size() == 1) {
        analysis.findings.push_back(Finding{
            "every incident is in MCA bank " + std::to_string(analysis.per_bank.front().value),
            "A single bank across all incidents points at one functional unit rather than a "
            "general instability. It does not by itself identify which core is at fault, "
            "because the bank number is per-core.",
            Confidence::Moderate});
    }

    if (!analysis.per_apic.empty()) {
        const CountedValue& top = analysis.per_apic.front();
        const bool concentrated =
            analysis.per_apic.size() > 1 && top.count * 2 >= analysis.incident_count;
        if (concentrated) {
            analysis.findings.push_back(Finding{
                "APIC " + std::to_string(top.value) + " reports " + std::to_string(top.count) +
                    " of " + std::to_string(analysis.incident_count) + " incidents",
                "One core reporting disproportionately often suggests that core is the weak "
                "one. Treat this as a lead rather than a conclusion: an uncorrectable error is "
                "broadcast, and which core wins the race to log it is not entirely random but "
                "is not proof of origin either.",
                Confidence::Moderate});
        } else if (analysis.per_apic.size() > 2) {
            analysis.findings.push_back(Finding{
                "the incidents are spread over " + std::to_string(analysis.per_apic.size()) +
                    " different cores",
                "No single core dominates, which argues against one defective core and for "
                "something shared - the memory controller, the interconnect, or a voltage or "
                "clock margin that affects the whole die.",
                Confidence::Moderate});
        }
    }

    switch (analysis.trend) {
        case RateTrend::Accelerating:
            analysis.findings.push_back(Finding{
                "the failure rate is accelerating",
                "The gaps between incidents are getting shorter. Progressive silicon "
                "degradation behaves like this; a fixed marginality does not. Expect the "
                "interval to keep shortening.",
                Confidence::Moderate});
            break;
        case RateTrend::Flat:
            analysis.findings.push_back(Finding{
                "the failure rate is flat",
                "A constant rate argues against progressive degradation and for a fixed "
                "marginality - a voltage, clock or timing setting that is slightly out of "
                "range and fails whenever conditions line up.",
                Confidence::Moderate});
            break;
        case RateTrend::Decelerating:
            analysis.findings.push_back(Finding{
                "the failure rate is slowing",
                "Incidents are getting further apart. If something was changed recently - a "
                "BIOS setting, a memory profile, a cooling fix - this is consistent with it "
                "having helped.",
                Confidence::Weak});
            break;
        case RateTrend::TooFewSamples:
            analysis.findings.push_back(Finding{
                "there are too few incidents to judge the trend",
                "At least five incidents are needed before an accelerating and a flat rate "
                "can be told apart. Until then, no claim about degradation is supportable.",
                Confidence::Weak});
            break;
    }

    if (analysis.addresses.measurable) {
        if (analysis.addresses.clustered) {
            analysis.findings.push_back(Finding{
                "the faulting addresses cluster",
                "Repeated addresses in the same pages suggest a defective physical structure - "
                "a cache way, a TLB entry, a DIMM cell - rather than a general timing problem.",
                Confidence::Moderate});
        } else {
            analysis.findings.push_back(Finding{
                "the faulting addresses scatter",
                "The addresses are spread across " +
                    std::to_string(analysis.addresses.distinct_pages) +
                    " distinct pages with no repetition. That argues against one broken "
                    "structure and for a timing or voltage marginality that can corrupt "
                    "anything in flight.",
                Confidence::Moderate});
        }
    }

    if (analysis.install_date.has_value() && analysis.first_seen.has_value()) {
        const std::int64_t age = *analysis.first_seen - *analysis.install_date;
        if (age > 0) {
            analysis.findings.push_back(Finding{
                "the first incident is " + text::format_span(age) + " after the OS install",
                "A long clean period before the first incident argues against a configuration "
                "that was always wrong and for something that changed - degradation, a "
                "firmware update, or a change in workload or ambient temperature.",
                age > 30LL * 86400 ? Confidence::Moderate : Confidence::Weak});
        }
    }

    // --- Verdict -----------------------------------------------------------

    if (fatal > 0 && analysis.trend == RateTrend::Flat && !analysis.addresses.clustered) {
        analysis.verdict =
            "Evidence points at a fixed marginality rather than a failing part: uncorrectable "
            "machine checks at a steady rate, scattered addresses, no single dominant core. "
            "The usual causes are core voltage or fabric/memory timing under light load. This "
            "is a weighing of evidence, not a diagnosis.";
    } else if (fatal > 0 && analysis.trend == RateTrend::Accelerating) {
        analysis.verdict =
            "Evidence leans towards progressive degradation: uncorrectable machine checks at a "
            "shortening interval. If the rate keeps rising, the part is getting worse rather "
            "than sitting at a fixed margin.";
    } else if (fatal > 0 && analysis.trend == RateTrend::Decelerating) {
        analysis.verdict =
            "Uncorrectable machine checks with processor context corrupt, but the interval "
            "between them is lengthening. If anything was changed recently - a BIOS setting, a "
            "memory profile, cooling - this is consistent with it having helped. Keep "
            "watching: a falling rate is not the same as a fixed fault.";
    } else if (fatal > 0) {
        analysis.verdict =
            "There are uncorrectable machine checks with processor context corrupt, which "
            "explains crashes that leave no dump. There is not yet enough history to say "
            "whether the rate is stable or worsening.";
    } else {
        analysis.verdict =
            "Only corrected errors are present. These are logged for trending and had no "
            "immediate impact, but a rising corrected-error rate often precedes uncorrected "
            "ones.";
    }

    return analysis;
}

}  // namespace postmortem::events
