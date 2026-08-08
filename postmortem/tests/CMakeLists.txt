# The test executable links postmortem_core only - never postmortem_platform.
# That is what enforces the "decoder logic stays platform-independent" rule
# from CLAUDE.md: if a Windows dependency creeps into core, this target stops
# linking.
add_executable(postmortem_tests
    test_main.cpp
    test_args.cpp
    test_cper.cpp
    test_events.cpp
    test_input.cpp
    test_json.cpp
    test_json_reader.cpp
    test_live.cpp
    test_mca.cpp
    test_signature.cpp
    test_table.cpp)

target_link_libraries(postmortem_tests PRIVATE
    postmortem_options
    postmortem_core)

target_include_directories(postmortem_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME unit COMMAND postmortem_tests)
