#include "platform/etw.hpp"

#include <windows.h>

#include <evntrace.h>
#include <evntcons.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include "platform/strings.hpp"

namespace postmortem::platform {
namespace {

// MOF class GUIDs for the kernel logger's classic events. With
// PROCESS_TRACE_MODE_EVENT_RECORD these arrive in EVENT_RECORD with the class
// GUID in EventHeader.ProviderId and the event type in
// EventHeader.EventDescriptor.Opcode.
//
// Thread  {3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c}, opcode 36 = CSwitch
// PerfInfo{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}, 66 = DPC, 67 = ISR,
//                                                 68 = ThreadDPC, 69 = TimerDPC
constexpr GUID kThreadGuid = {
    0x3d6fa8d1, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
constexpr GUID kPerfInfoGuid = {
    0xce1dbfb4, 0x137e, 0x4da6, {0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc}};

// SystemTraceControlGuid, spelled out rather than referenced from evntrace.h:
// the header only defines the symbol when INITGUID is set, and defining that
// in one translation unit of a static library is a link-order trap.
constexpr GUID kSystemTraceControlGuid = {
    0x9e814aad, 0x3204, 0x11d2, {0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}};

constexpr UCHAR kOpcodeCSwitch = 36;
constexpr UCHAR kOpcodeSampledProfile = 46;
constexpr UCHAR kOpcodeDpc = 66;
constexpr UCHAR kOpcodeIsr = 67;
constexpr UCHAR kOpcodeThreadDpc = 68;
constexpr UCHAR kOpcodeTimerDpc = 69;

// Bounds on what the callback keeps. A 32-thread machine produces ~32k
// samples a second; without a cap the distinct-stack map would grow without
// limit between frames.
constexpr std::size_t kMaxFrames = 48;
constexpr std::size_t kMaxDistinctStacks = 4096;

// x86-64 kernel addresses are the high canonical half.
constexpr std::uint64_t kKernelSpace = 0xFFFF800000000000ull;

bool same_guid(const GUID& a, const GUID& b) {
    return std::memcmp(&a, &b, sizeof(GUID)) == 0;
}

// An elevated token holds SeSystemProfilePrivilege but leaves it disabled;
// sample-based profiling fails without it being switched on explicitly.
bool enable_privilege(const wchar_t* name) {
    HANDLE token = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                           &token) == FALSE) {
        return false;
    }

    LUID luid{};
    if (::LookupPrivilegeValueW(nullptr, name, &luid) == FALSE) {
        ::CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    const BOOL adjusted =
        ::AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
    // AdjustTokenPrivileges reports success even when the privilege was not
    // held, so the last error has to be checked too.
    const bool ok = adjusted != FALSE && ::GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    ::CloseHandle(token);
    return ok;
}

std::string error_text(DWORD code) {
    LPWSTR buffer = nullptr;
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::string message;
    if (length > 0 && buffer != nullptr) {
        message = trim(to_utf8(std::wstring_view(buffer, length)));
    }
    if (buffer != nullptr) ::LocalFree(buffer);
    if (message.empty()) message = "error " + std::to_string(code);
    return message;
}

}  // namespace

struct EtwSession::Impl {
    // The properties block must be one allocation with room for the session
    // name after it; StartTrace writes the name into that tail.
    std::vector<std::byte> properties;
    TRACEHANDLE session = 0;
    TRACEHANDLE consumer = INVALID_PROCESSTRACE_HANDLE;
    std::thread worker;
    std::atomic<bool> stopping{false};

    unsigned processor_count = 0;
    std::vector<std::atomic<std::uint64_t>> context_switches;
    std::vector<std::atomic<std::uint64_t>> dpcs;
    std::vector<std::atomic<std::uint64_t>> interrupts;
    std::atomic<std::uint64_t> unattributed{0};

    // Stack aggregation. ProcessTrace runs the callback on a single thread, so
    // the map needs no lock of its own; the mutex only guards the handoff to
    // whoever calls take_stacks().
    bool sample_stacks = false;
    std::mutex stack_mutex;
    struct StackBucket {
        std::vector<std::uint64_t> frames;
        std::uint32_t process_id = 0;
        std::uint64_t count = 0;
    };
    std::unordered_map<std::uint64_t, StackBucket> stacks;
    std::uint64_t stack_total = 0;
    std::uint64_t stack_kernel = 0;
    std::uint64_t stack_user = 0;
    std::uint64_t stack_dropped = 0;

    explicit Impl(unsigned count)
        : processor_count(count),
          context_switches(count),
          dpcs(count),
          interrupts(count) {
        for (unsigned i = 0; i < count; ++i) {
            context_switches[i].store(0);
            dpcs[i].store(0);
            interrupts[i].store(0);
        }
    }

    EVENT_TRACE_PROPERTIES* props() {
        return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties.data());
    }
};

namespace {

// Runs on ETW's consumer thread for every buffered event. Kept to header
// fields and atomic increments only - no TDH property parsing - because this
// is called for hundreds of thousands of events per second and anything
// heavier would drop buffers.
// Pulls the call stack out of an event's extended data. The kernel attaches it
// as EVENT_HEADER_EXT_TYPE_STACK_TRACE64 when stack tracing is enabled for
// that event type, captured inside the profiling interrupt - which is why
// nothing has to be suspended to obtain it.
const EVENT_EXTENDED_ITEM_STACK_TRACE64* find_stack(PEVENT_RECORD record,
                                                    std::size_t& frame_count) {
    frame_count = 0;
    for (USHORT i = 0; i < record->ExtendedDataCount; ++i) {
        const EVENT_HEADER_EXTENDED_DATA_ITEM& item = record->ExtendedData[i];
        if (item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE64) continue;
        if (item.DataSize < sizeof(ULONG64)) continue;

        const auto* trace =
            reinterpret_cast<const EVENT_EXTENDED_ITEM_STACK_TRACE64*>(item.DataPtr);
        // DataSize covers MatchId plus the address array.
        frame_count = (item.DataSize - sizeof(ULONG64)) / sizeof(ULONG64);
        return trace;
    }
    return nullptr;
}

void record_stack(EtwSession::Impl* impl, PEVENT_RECORD record) {
    std::size_t frame_count = 0;
    const EVENT_EXTENDED_ITEM_STACK_TRACE64* trace = find_stack(record, frame_count);
    if (trace == nullptr || frame_count == 0) return;

    frame_count = std::min(frame_count, kMaxFrames);

    // FNV-1a over the addresses plus the pid: cheap, and collisions only merge
    // two stacks in the display rather than corrupting anything.
    std::uint64_t hash = 1469598103934665603ull;
    const auto mix = [&hash](std::uint64_t value) {
        hash ^= value;
        hash *= 1099511628211ull;
    };
    mix(record->EventHeader.ProcessId);
    for (std::size_t i = 0; i < frame_count; ++i) mix(trace->Address[i]);

    ++impl->stack_total;
    if (trace->Address[0] >= kKernelSpace) {
        ++impl->stack_kernel;
    } else {
        ++impl->stack_user;
    }

    const auto found = impl->stacks.find(hash);
    if (found != impl->stacks.end()) {
        ++found->second.count;
        return;
    }
    if (impl->stacks.size() >= kMaxDistinctStacks) {
        ++impl->stack_dropped;
        return;
    }

    EtwSession::Impl::StackBucket bucket;
    bucket.process_id = record->EventHeader.ProcessId;
    bucket.count = 1;
    bucket.frames.assign(trace->Address, trace->Address + frame_count);
    impl->stacks.emplace(hash, std::move(bucket));
}

void WINAPI on_event(PEVENT_RECORD record) {
    auto* impl = static_cast<EtwSession::Impl*>(record->UserContext);
    if (impl == nullptr) return;

    const UCHAR opcode = record->EventHeader.EventDescriptor.Opcode;

    if (impl->sample_stacks && opcode == kOpcodeSampledProfile &&
        same_guid(record->EventHeader.ProviderId, kPerfInfoGuid)) {
        record_stack(impl, record);
        return;
    }
    const bool is_cswitch =
        same_guid(record->EventHeader.ProviderId, kThreadGuid) && opcode == kOpcodeCSwitch;
    const bool is_dpc = same_guid(record->EventHeader.ProviderId, kPerfInfoGuid) &&
                        (opcode == kOpcodeDpc || opcode == kOpcodeThreadDpc ||
                         opcode == kOpcodeTimerDpc);
    const bool is_isr =
        same_guid(record->EventHeader.ProviderId, kPerfInfoGuid) && opcode == kOpcodeIsr;

    if (!is_cswitch && !is_dpc && !is_isr) return;

    const unsigned processor = record->BufferContext.ProcessorIndex;
    if (processor >= impl->processor_count) {
        impl->unattributed.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    if (is_cswitch) {
        impl->context_switches[processor].fetch_add(1, std::memory_order_relaxed);
    } else if (is_dpc) {
        impl->dpcs[processor].fetch_add(1, std::memory_order_relaxed);
    } else {
        impl->interrupts[processor].fetch_add(1, std::memory_order_relaxed);
    }
}

ULONG WINAPI on_buffer(PEVENT_TRACE_LOGFILEW logfile) {
    auto* impl = static_cast<EtwSession::Impl*>(logfile->Context);
    // Returning FALSE makes ProcessTrace return, which is how stop() unblocks
    // the worker thread.
    return (impl != nullptr && impl->stopping.load()) ? FALSE : TRUE;
}

}  // namespace

EtwSession::~EtwSession() {
    stop();
}

bool EtwSession::start(unsigned processor_count, bool sample_stacks, std::string& error) {
    stop();
    if (processor_count == 0) {
        error = "no processors to trace";
        return false;
    }

    auto impl = std::make_unique<Impl>(processor_count);
    impl->sample_stacks = sample_stacks;

    // Profiling needs SeSystemProfilePrivilege. An elevated token holds it but
    // disabled; it has to be enabled explicitly.
    if (sample_stacks && !enable_privilege(SE_SYSTEM_PROFILE_NAME)) {
        error = "cannot enable SeSystemProfilePrivilege, which sampled profiling requires";
        return false;
    }

    const std::wstring name = KERNEL_LOGGER_NAMEW;
    const std::size_t size = sizeof(EVENT_TRACE_PROPERTIES) + (name.size() + 1) * sizeof(wchar_t);
    impl->properties.assign(size, std::byte{});

    EVENT_TRACE_PROPERTIES* props = impl->props();
    props->Wnode.BufferSize = static_cast<ULONG>(size);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;   // QPC timestamps
    props->Wnode.Guid = kSystemTraceControlGuid;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->EnableFlags = EVENT_TRACE_FLAG_CSWITCH | EVENT_TRACE_FLAG_DPC |
                         EVENT_TRACE_FLAG_INTERRUPT;
    if (sample_stacks) props->EnableFlags |= EVENT_TRACE_FLAG_PROFILE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    // Bigger, more numerous buffers than the default: a busy 32-thread machine
    // produces enough context switches to drop events otherwise.
    props->BufferSize = 128;
    props->MinimumBuffers = 32;
    props->MaximumBuffers = 128;
    props->FlushTimer = 1;

    TRACEHANDLE session = 0;
    ULONG status = ::StartTraceW(&session, name.c_str(), props);

    if (status == ERROR_ALREADY_EXISTS) {
        // Only one NT Kernel Logger exists system-wide. Something else owns it
        // - often a profiler left running. Stop it and retry once rather than
        // failing outright, but say so if that does not work either.
        ::ControlTraceW(0, name.c_str(), props, EVENT_TRACE_CONTROL_STOP);

        props->Wnode.BufferSize = static_cast<ULONG>(size);
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext = 1;
        props->Wnode.Guid = kSystemTraceControlGuid;
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props->EnableFlags = EVENT_TRACE_FLAG_CSWITCH | EVENT_TRACE_FLAG_DPC |
                             EVENT_TRACE_FLAG_INTERRUPT;
        if (sample_stacks) props->EnableFlags |= EVENT_TRACE_FLAG_PROFILE;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        props->BufferSize = 128;
        props->MinimumBuffers = 32;
        props->MaximumBuffers = 128;
        props->FlushTimer = 1;

        status = ::StartTraceW(&session, name.c_str(), props);
    }

    if (status != ERROR_SUCCESS) {
        if (status == ERROR_ACCESS_DENIED) {
            error = "kernel tracing needs an elevated process";
        } else if (status == ERROR_ALREADY_EXISTS) {
            error = "the NT Kernel Logger is already in use by another tool and could not be "
                    "taken over";
        } else {
            error = "StartTrace failed: " + error_text(status);
        }
        return false;
    }
    impl->session = session;

    if (sample_stacks) {
        // Ask the kernel to attach a call stack to every SampledProfile event.
        // Without this the profile events arrive with no stack at all.
        CLASSIC_EVENT_ID stack_event{};
        stack_event.EventGuid = kPerfInfoGuid;
        stack_event.Type = kOpcodeSampledProfile;
        const ULONG stack_status = ::TraceSetInformation(
            session, TraceStackTracingInfo, &stack_event, sizeof(stack_event));
        if (stack_status != ERROR_SUCCESS) {
            error = "the session started but stack tracing could not be enabled: " +
                    error_text(stack_status);
            ::ControlTraceW(session, nullptr, impl->props(), EVENT_TRACE_CONTROL_STOP);
            return false;
        }
        sampling_stacks_ = true;
    }

    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(name.c_str());
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = on_event;
    logfile.BufferCallback = on_buffer;
    logfile.Context = impl.get();

    const TRACEHANDLE consumer = ::OpenTraceW(&logfile);
    if (consumer == INVALID_PROCESSTRACE_HANDLE) {
        error = "OpenTrace failed: " + error_text(::GetLastError());
        ::ControlTraceW(session, nullptr, impl->props(), EVENT_TRACE_CONTROL_STOP);
        return false;
    }
    impl->consumer = consumer;

    Impl* raw = impl.release();
    impl_ = raw;
    running_ = true;

    // ProcessTrace blocks until the session stops or the buffer callback
    // returns FALSE, so it needs its own thread.
    raw->worker = std::thread([raw]() {
        TRACEHANDLE handle = raw->consumer;
        ::ProcessTrace(&handle, 1, nullptr, nullptr);
    });

    return true;
}

void EtwSession::stop() {
    if (impl_ == nullptr) return;

    impl_->stopping.store(true);

    // Stopping the session is what makes ProcessTrace return; the buffer
    // callback covers the case where it has not noticed yet.
    if (impl_->session != 0) {
        ::ControlTraceW(impl_->session, nullptr, impl_->props(), EVENT_TRACE_CONTROL_STOP);
    }
    if (impl_->consumer != INVALID_PROCESSTRACE_HANDLE) {
        ::CloseTrace(impl_->consumer);
    }
    if (impl_->worker.joinable()) impl_->worker.join();

    delete impl_;
    impl_ = nullptr;
    running_ = false;
    sampling_stacks_ = false;
}

EtwCounts EtwSession::take() {
    EtwCounts counts;
    if (impl_ == nullptr) return counts;

    counts.context_switches.resize(impl_->processor_count);
    counts.dpcs.resize(impl_->processor_count);
    counts.interrupts.resize(impl_->processor_count);

    for (unsigned i = 0; i < impl_->processor_count; ++i) {
        counts.context_switches[i] = impl_->context_switches[i].exchange(0);
        counts.dpcs[i] = impl_->dpcs[i].exchange(0);
        counts.interrupts[i] = impl_->interrupts[i].exchange(0);

        counts.total_context_switches += counts.context_switches[i];
        counts.total_dpcs += counts.dpcs[i];
        counts.total_interrupts += counts.interrupts[i];
    }
    counts.unattributed = impl_->unattributed.exchange(0);
    return counts;
}

StackSamples EtwSession::take_stacks(std::size_t limit) {
    StackSamples samples;
    if (impl_ == nullptr || !impl_->sample_stacks) return samples;

    std::unordered_map<std::uint64_t, Impl::StackBucket> taken;
    {
        // The callback thread owns the map between takes; swap it out rather
        // than holding the lock while sorting and copying.
        std::lock_guard<std::mutex> guard(impl_->stack_mutex);
        taken.swap(impl_->stacks);
        samples.total = impl_->stack_total;
        samples.kernel_samples = impl_->stack_kernel;
        samples.user_samples = impl_->stack_user;
        samples.dropped = impl_->stack_dropped;
        impl_->stack_total = 0;
        impl_->stack_kernel = 0;
        impl_->stack_user = 0;
        impl_->stack_dropped = 0;
    }

    samples.stacks.reserve(taken.size());
    for (auto& [hash, bucket] : taken) {
        (void)hash;
        StackSample sample;
        sample.process_id = bucket.process_id;
        sample.count = bucket.count;
        sample.frames = std::move(bucket.frames);
        samples.stacks.push_back(std::move(sample));
    }

    std::sort(samples.stacks.begin(), samples.stacks.end(),
              [](const StackSample& a, const StackSample& b) { return a.count > b.count; });
    if (limit > 0 && samples.stacks.size() > limit) samples.stacks.resize(limit);
    return samples;
}

}  // namespace postmortem::platform
