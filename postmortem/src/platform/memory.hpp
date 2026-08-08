// Read-only inspection of another process's memory.
//
// ReadProcessMemory needs no suspension and no driver: the target keeps
// running while it is read. The trade-off is that a multi-byte value can be
// caught mid-write and read torn - the reader sees a real state the memory
// passed through, just possibly not one the program intended to be observable.
//
// Kernel memory is out of reach entirely; this is user address space only.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace postmortem::platform {

struct MemoryRegion {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool image = false;      // backed by a mapped module
    bool is_private = false;
    std::string module;      // owning module, when the region is an image
};

struct ProcessTarget {
    bool ok = false;
    std::string error;
    std::string name;
    std::uint32_t process_id = 0;
};

// Holds the process handle for the life of a watch.
class ProcessMemory {
public:
    ProcessMemory() = default;
    ~ProcessMemory();

    ProcessMemory(const ProcessMemory&) = delete;
    ProcessMemory& operator=(const ProcessMemory&) = delete;

    [[nodiscard]] ProcessTarget open(std::uint32_t process_id);
    void close();
    [[nodiscard]] bool is_open() const { return handle_ != nullptr; }

    // Reads `length` bytes. A short read is not an error: a region can be
    // decommitted while being watched, and reporting how much was readable is
    // more useful than failing the whole frame.
    [[nodiscard]] bool read(std::uint64_t address, std::size_t length,
                            std::vector<std::uint8_t>& out, std::size_t& read_bytes) const;

    [[nodiscard]] std::vector<MemoryRegion> regions() const;

    // Base address of a loaded module by name, for `--module`.
    [[nodiscard]] std::uint64_t module_base(const std::string& name) const;

private:
    void* handle_ = nullptr;
};

// Resolves a process by numeric id or by executable name. A name that matches
// several processes is reported rather than guessed at.
struct ProcessLookup {
    bool ok = false;
    std::uint32_t process_id = 0;
    std::string name;
    std::string error;
    std::vector<std::pair<std::uint32_t, std::string>> candidates;
};
[[nodiscard]] ProcessLookup find_process(const std::string& id_or_name);

}  // namespace postmortem::platform
