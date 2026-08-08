cmake_minimum_required(VERSION 3.20)

project(postmortem
    VERSION     0.1.0
    DESCRIPTION "Windows CPU/platform stability diagnostic CLI"
    LANGUAGES   CXX)

# The version the binary prints lives in src/core/version.hpp so that the
# Visual Studio project builds without CMake having to inject a quoted macro.
# Fail loudly rather than silently shipping two different version numbers.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/core/version.hpp" _pm_version_header)
string(REGEX MATCH "kVersion = \"([0-9]+\\.[0-9]+\\.[0-9]+)\"" _pm_match "${_pm_version_header}")
if(NOT CMAKE_MATCH_1)
    message(FATAL_ERROR "could not find kVersion in src/core/version.hpp")
endif()
if(NOT CMAKE_MATCH_1 VERSION_EQUAL PROJECT_VERSION)
    message(FATAL_ERROR
        "version mismatch: project() says ${PROJECT_VERSION} but "
        "src/core/version.hpp says ${CMAKE_MATCH_1}")
endif()

# ---------------------------------------------------------------------------
# Platform gate (spec §3)
#
# x64 only: the MCA/CPER decoding is x86-specific, and the CPUID-based topology
# enumeration has no meaning on ARM64. Refuse at configure time rather than
# emitting a binary that would mis-decode. A runtime check for "x64 binary
# running under emulation on an ARM64 host" lives in src/platform/arch.cpp.
# ---------------------------------------------------------------------------
if(NOT WIN32)
    message(FATAL_ERROR
        "postmortem targets Windows only: it reads the Windows event log and "
        "SMBIOS/registry state. Current system: ${CMAKE_SYSTEM_NAME}.")
endif()

if(CMAKE_VS_PLATFORM_NAME)
    set(_pm_arch "${CMAKE_VS_PLATFORM_NAME}")
elseif(CMAKE_CXX_COMPILER_ARCHITECTURE_ID)
    set(_pm_arch "${CMAKE_CXX_COMPILER_ARCHITECTURE_ID}")
else()
    set(_pm_arch "${CMAKE_SYSTEM_PROCESSOR}")
endif()
string(TOLOWER "${_pm_arch}" _pm_arch)

if(NOT _pm_arch MATCHES "^(x64|amd64|x86_64)$")
    message(FATAL_ERROR
        "postmortem is x64-only (spec §3) but the target architecture is "
        "'${_pm_arch}'.\n"
        "  Visual Studio generator: pass -A x64 (the bundled presets do).\n"
        "  Ninja + cl: configure from an x64 Native Tools Command Prompt.")
endif()

# ---------------------------------------------------------------------------
# Global build settings
# ---------------------------------------------------------------------------
option(POSTMORTEM_BUILD_TESTS "Build the postmortem unit tests" ON)
option(POSTMORTEM_WERROR      "Treat compiler warnings as errors" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Spec §2/§3: ship a standalone .exe with no runtime install step. The UCRT is
# part of Windows, but vcruntime140/msvcp140 are not - static-link them so the
# binary can be copied onto a machine that is mid-diagnosis without dragging a
# redistributable along.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endif()

# Interface target carrying the settings every postmortem target needs.
add_library(postmortem_options INTERFACE)
target_compile_features(postmortem_options INTERFACE cxx_std_20)

target_compile_definitions(postmortem_options INTERFACE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX)

if(MSVC)
    target_compile_options(postmortem_options INTERFACE
        /W4
        /permissive-
        /utf-8
        /EHsc
        /Zc:__cplusplus
        /Zc:preprocessor
        /Zc:inline)
    if(POSTMORTEM_WERROR)
        target_compile_options(postmortem_options INTERFACE /WX)
    endif()
    # clang-cl accepts the MSVC flags above; silence the few warnings it raises
    # that /W4 does not have an equivalent for.
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        target_compile_options(postmortem_options INTERFACE
            -Wno-unused-command-line-argument)
    endif()
endif()

# ---------------------------------------------------------------------------
# postmortem_core - platform-independent code
#
# Hard rule (CLAUDE.md): nothing in this target may include <windows.h> or any
# other Windows header. The CPER/MCA decoders land here in milestone 2 so their
# tests run anywhere; the CLI parser and output formatting live here for the
# same reason.
# ---------------------------------------------------------------------------
add_library(postmortem_core STATIC
    src/core/cli/args.cpp
    src/core/cli/usage.cpp
    src/core/cper/guid.cpp
    src/core/cper/record.cpp
    src/core/cper/sections.cpp
    src/core/cpu/signature.cpp
    src/core/events/analysis.cpp
    src/core/events/event.cpp
    src/core/events/crash_timeline.cpp
    src/core/events/whea.cpp
    src/core/input/values.cpp
    src/core/json/reader.cpp
    src/core/json/writer.cpp
    src/core/mca/registers.cpp
    src/core/render/decode_view.cpp
    src/core/render/event_view.cpp
    src/core/text/format.cpp
    src/core/text/table.cpp
    src/core/xml/parse.cpp)

target_include_directories(postmortem_core PUBLIC src)
target_link_libraries(postmortem_core PUBLIC postmortem_options)

# ---------------------------------------------------------------------------
# postmortem_platform - everything that touches Win32
# ---------------------------------------------------------------------------
add_library(postmortem_platform STATIC
    src/platform/arch.cpp
    src/platform/console.cpp
    src/platform/cpu_info.cpp
    src/platform/eventlog.cpp
    src/platform/file.cpp
    src/platform/os_info.cpp
    src/platform/power.cpp
    src/platform/registry.cpp
    src/platform/smbios.cpp
    src/platform/state.cpp
    src/platform/strings.cpp
    src/platform/cpu_topology.cpp)

target_include_directories(postmortem_platform PUBLIC src)
target_link_libraries(postmortem_platform
    PUBLIC  postmortem_options
            postmortem_core
    PRIVATE advapi32    # registry
            wevtapi     # event log
            powrprof    # power schemes and processor power information
            ole32)      # SHGetKnownFolderPath / CLSIDFromString

# ---------------------------------------------------------------------------
# pm.exe
# ---------------------------------------------------------------------------
add_executable(pm
    src/main.cpp
    src/commands/common.cpp
    src/commands/decode.cpp
    src/commands/mitigate.cpp
    src/commands/report.cpp
    src/commands/scan.cpp
    src/commands/status.cpp
    src/commands/timeline.cpp
    src/commands/topology.cpp
    src/commands/watch.cpp)

target_link_libraries(pm PRIVATE
    postmortem_options
    postmortem_core
    postmortem_platform
    shell32)            # CommandLineToArgvW

set_target_properties(pm PROPERTIES OUTPUT_NAME "pm")

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(POSTMORTEM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
