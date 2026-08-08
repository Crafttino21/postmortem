#include "platform/perf.hpp"

#include <windows.h>

#include <pdh.h>
#include <pdhmsg.h>

#include <algorithm>
#include <map>

#include "platform/strings.hpp"

namespace postmortem::platform {
namespace {

// Which member of CoreSample a counter feeds.
enum class Field {
    ProcessorTime,
    IdleTime,
    ProcessorPerformance,
    Frequency,
    C1Time,
    C2Time,
    C3Time,
    Interrupts,
    Dpcs,
    Parking,
};

struct CounterSpec {
    const wchar_t* path;
    const char* name;
    Field field;
    bool required;
};

// The "Processor Information" set is per logical processor and, unlike the
// older "Processor" set, is group-aware - instances are named "<group>,<cpu>".
//
// Paths are given in English and added with PdhAddEnglishCounterW, because
// counter names are localised: on a German Windows this set is
// "Prozessorinformationen" and the English path would simply not resolve.
constexpr CounterSpec kCounters[] = {
    {L"\\Processor Information(*)\\% Processor Time", "% Processor Time",
     Field::ProcessorTime, true},
    {L"\\Processor Information(*)\\% Idle Time", "% Idle Time", Field::IdleTime, false},
    {L"\\Processor Information(*)\\% Processor Performance", "% Processor Performance",
     Field::ProcessorPerformance, false},
    {L"\\Processor Information(*)\\Processor Frequency", "Processor Frequency",
     Field::Frequency, false},
    {L"\\Processor Information(*)\\% C1 Time", "% C1 Time", Field::C1Time, false},
    {L"\\Processor Information(*)\\% C2 Time", "% C2 Time", Field::C2Time, false},
    {L"\\Processor Information(*)\\% C3 Time", "% C3 Time", Field::C3Time, false},
    {L"\\Processor Information(*)\\Interrupts/sec", "Interrupts/sec", Field::Interrupts, false},
    {L"\\Processor Information(*)\\DPCs Queued/sec", "DPCs Queued/sec", Field::Dpcs, false},
    {L"\\Processor Information(*)\\Parking Status", "Parking Status", Field::Parking, false},
};

// Instance names look like "0,5" (group 0, processor 5), plus "_Total" and, on
// multi-group machines, "0,_Total". Returns false for the aggregates.
bool parse_instance(const std::wstring& name, unsigned& group, unsigned& index) {
    const std::size_t comma = name.find(L',');
    if (comma == std::wstring::npos) return false;

    const std::wstring group_text = name.substr(0, comma);
    const std::wstring index_text = name.substr(comma + 1);
    if (group_text.empty() || index_text.empty()) return false;

    const auto all_digits = [](const std::wstring& text) {
        return std::all_of(text.begin(), text.end(),
                           [](wchar_t c) { return c >= L'0' && c <= L'9'; });
    };
    if (!all_digits(group_text) || !all_digits(index_text)) return false;

    group = static_cast<unsigned>(std::stoul(group_text));
    index = static_cast<unsigned>(std::stoul(index_text));
    return true;
}

void assign(CoreSample& sample, Field field, double value) {
    switch (field) {
        case Field::ProcessorTime:        sample.processor_time = value; break;
        case Field::IdleTime:             sample.idle_time = value; break;
        case Field::ProcessorPerformance: sample.processor_performance = value; break;
        case Field::Frequency:            sample.frequency_mhz = value; break;
        case Field::C1Time:               sample.c1_time = value; break;
        case Field::C2Time:               sample.c2_time = value; break;
        case Field::C3Time:               sample.c3_time = value; break;
        case Field::Interrupts:           sample.interrupts_per_sec = value; break;
        case Field::Dpcs:                 sample.dpcs_per_sec = value; break;
        case Field::Parking:              sample.parked = value >= 0.5; break;
    }
}

}  // namespace

struct PerfMonitor::Counter {
    PDH_HCOUNTER handle = nullptr;
    Field field = Field::ProcessorTime;
    std::string name;
};

PerfMonitor::~PerfMonitor() {
    close();
}

bool PerfMonitor::open(std::string& error) {
    close();

    PDH_HQUERY query = nullptr;
    const PDH_STATUS status = ::PdhOpenQueryW(nullptr, 0, &query);
    if (status != ERROR_SUCCESS) {
        error = "PdhOpenQuery failed (0x" + std::to_string(status) + ")";
        return false;
    }
    query_ = query;

    for (const CounterSpec& spec : kCounters) {
        PDH_HCOUNTER handle = nullptr;
        const PDH_STATUS added = ::PdhAddEnglishCounterW(query, spec.path, 0, &handle);
        if (added != ERROR_SUCCESS) {
            if (spec.required) {
                error = std::string("the performance counter '") + spec.name +
                        "' is not available; the performance counter registry may need "
                        "rebuilding (lodctr /R)";
                close();
                return false;
            }
            missing_.emplace_back(spec.name);
            continue;
        }

        auto* counter = new Counter{handle, spec.field, spec.name};
        counters_.push_back(counter);
    }

    // Prime the rate counters: they need a previous sample to divide against.
    ::PdhCollectQueryData(query);
    primed_ = true;
    return true;
}

void PerfMonitor::close() {
    for (Counter* counter : counters_) delete counter;
    counters_.clear();

    if (query_ != nullptr) {
        ::PdhCloseQuery(static_cast<PDH_HQUERY>(query_));
        query_ = nullptr;
    }
    missing_.clear();
    primed_ = false;
}

PerfSnapshot PerfMonitor::sample() {
    PerfSnapshot snapshot;
    snapshot.missing_counters = missing_;

    if (query_ == nullptr) {
        snapshot.error = "the performance query is not open";
        return snapshot;
    }

    const PDH_STATUS status = ::PdhCollectQueryData(static_cast<PDH_HQUERY>(query_));
    if (status != ERROR_SUCCESS) {
        snapshot.error = "PdhCollectQueryData failed (0x" + std::to_string(status) + ")";
        return snapshot;
    }

    std::map<std::pair<unsigned, unsigned>, CoreSample> cores;

    for (const Counter* counter : counters_) {
        DWORD size = 0;
        DWORD count = 0;
        PDH_STATUS result = ::PdhGetFormattedCounterArrayW(counter->handle, PDH_FMT_DOUBLE,
                                                           &size, &count, nullptr);
        if (result != PDH_MORE_DATA || size == 0) continue;

        std::vector<std::byte> buffer(size);
        auto* items = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(buffer.data());
        result = ::PdhGetFormattedCounterArrayW(counter->handle, PDH_FMT_DOUBLE, &size, &count,
                                                items);
        if (result != ERROR_SUCCESS) continue;

        for (DWORD i = 0; i < count; ++i) {
            if (items[i].szName == nullptr) continue;
            // A counter can fail for one instance while succeeding for others;
            // skip those rather than writing a garbage value.
            if (items[i].FmtValue.CStatus != ERROR_SUCCESS &&
                items[i].FmtValue.CStatus != PDH_CSTATUS_VALID_DATA &&
                items[i].FmtValue.CStatus != PDH_CSTATUS_NEW_DATA) {
                continue;
            }

            const std::wstring name(items[i].szName);
            unsigned group = 0;
            unsigned index = 0;
            if (!parse_instance(name, group, index)) {
                if (name == L"_Total") {
                    assign(snapshot.total, counter->field, items[i].FmtValue.doubleValue);
                }
                continue;
            }

            CoreSample& core = cores[{group, index}];
            core.group = group;
            core.index_in_group = index;
            assign(core, counter->field, items[i].FmtValue.doubleValue);
        }
    }

    snapshot.cores.reserve(cores.size());
    for (auto& [key, core] : cores) {
        (void)key;
        snapshot.cores.push_back(core);
    }
    // Flat OS index across groups, matching how the topology map numbers them.
    std::sort(snapshot.cores.begin(), snapshot.cores.end(),
              [](const CoreSample& a, const CoreSample& b) {
                  if (a.group != b.group) return a.group < b.group;
                  return a.index_in_group < b.index_in_group;
              });
    for (std::size_t i = 0; i < snapshot.cores.size(); ++i) {
        snapshot.cores[i].os_index = static_cast<unsigned>(i);
    }

    snapshot.ok = !snapshot.cores.empty();
    if (!snapshot.ok) {
        snapshot.error = "no per-processor instances were returned";
    }
    return snapshot;
}

}  // namespace postmortem::platform
