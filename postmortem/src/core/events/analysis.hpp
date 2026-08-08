// Trend analysis (spec §4.6).
//
// "Frame conclusions as evidence with confidence levels, never as certainties."
// Every finding below therefore carries its own reasoning and a confidence,
// and the code says what would change its mind.

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/events/whea.hpp"

namespace postmortem::events {

enum class Confidence {
    Weak,        // consistent with the data, but so are other explanations
    Moderate,    // the data leans this way
    Strong,      // hard to explain otherwise
};

[[nodiscard]] std::string_view confidence_text(Confidence confidence);

struct Finding {
    std::string claim;
    std::string reasoning;
    Confidence confidence = Confidence::Weak;
};

enum class RateTrend {
    TooFewSamples,
    Flat,
    Accelerating,
    Decelerating,
};

[[nodiscard]] std::string_view rate_trend_text(RateTrend trend);

struct CountedValue {
    unsigned value = 0;
    std::size_t count = 0;
};

struct AddressClustering {
    bool measurable = false;
    std::size_t sample_count = 0;
    std::size_t distinct_pages = 0;      // distinct 4 KiB pages
    std::size_t largest_page_group = 0;
    bool clustered = false;
};

struct Analysis {
    std::size_t incident_count = 0;
    std::size_t record_count = 0;

    std::optional<std::int64_t> first_seen;
    std::optional<std::int64_t> last_seen;
    std::optional<std::int64_t> install_date;

    std::vector<CountedValue> per_apic;
    std::vector<CountedValue> per_bank;

    std::vector<std::int64_t> intervals;   // seconds between consecutive incidents
    std::optional<std::int64_t> median_interval;
    std::optional<std::int64_t> mean_interval;
    RateTrend trend = RateTrend::TooFewSamples;

    AddressClustering addresses;

    // Incidents per hour of day, index 0..23, in local time as supplied.
    std::array<std::size_t, 24> by_hour{};

    std::string verdict;
    std::vector<Finding> findings;
};

struct AnalysisInput {
    std::vector<Incident> incidents;
    std::optional<std::int64_t> install_date;
    // Maps a Unix timestamp to the local hour of day, so the pure analysis
    // does not need a timezone database.
    std::function<unsigned(std::int64_t)> local_hour;
};

[[nodiscard]] Analysis analyse(const AnalysisInput& input);

}  // namespace postmortem::events
