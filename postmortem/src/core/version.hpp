#pragma once

namespace postmortem {

// Single source of truth for the version string.
//
// It lives in a header rather than a compile definition so that both build
// systems - CMake and the Visual Studio project - agree without either having
// to inject a quoted macro. CMakeLists.txt parses this line and fails to
// configure if project(VERSION) drifts from it.
inline constexpr const char* kVersion = "0.1.0";

}  // namespace postmortem
