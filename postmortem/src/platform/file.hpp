#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace postmortem::platform {

struct FileResult {
    bool ok = false;
    std::vector<std::uint8_t> bytes;
    std::string error;
};

// Reads a whole file. The path arrives as UTF-8 and is widened before use, so
// `--cper @C:\Ablage\Störung.bin` works - a saved blob is exactly the kind of
// file that ends up in a directory with an umlaut in it.
[[nodiscard]] FileResult read_file(const std::string& utf8_path);

}  // namespace postmortem::platform
