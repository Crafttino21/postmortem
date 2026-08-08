// A ~60-line test harness.
//
// Spec §3 says keep dependencies minimal and ship no runtime install step;
// pulling Catch2 or doctest in via FetchContent would also make an offline
// build fail. The decoders in milestone 2 need nothing more than "run these
// functions, compare against these expected values", which is what this does.

#pragma once

#include <ostream>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace pmtest {

using TestFn = void (*)();

struct TestCase {
    std::string name;
    TestFn fn;
};

std::vector<TestCase>& registry();
void record_failure(const char* file, int line, const std::string& message);

struct Registrar {
    Registrar(const char* name, TestFn fn);
};

template <class T>
void stream_value(std::ostream& os, const T& value) {
    if constexpr (std::is_enum_v<T>) {
        os << static_cast<long long>(value);
    } else if constexpr (std::is_same_v<T, bool>) {
        os << (value ? "true" : "false");
    } else {
        os << value;
    }
}

template <class A, class B>
void check_equal(const char* file, int line, const char* actual_text, const char* expected_text,
                 const A& actual, const B& expected) {
    if (actual == expected) return;

    std::ostringstream message;
    message << actual_text << " == " << expected_text << "\n         actual:   ";
    stream_value(message, actual);
    message << "\n         expected: ";
    stream_value(message, expected);
    record_failure(file, line, message.str());
}

}  // namespace pmtest

#define PM_TEST(test_name)                                                  \
    static void test_name();                                                \
    static const ::pmtest::Registrar pm_registrar_##test_name(#test_name,   \
                                                              test_name);   \
    static void test_name()

#define PM_CHECK(expr)                                                      \
    do {                                                                    \
        if (!(expr)) {                                                      \
            ::pmtest::record_failure(__FILE__, __LINE__, "expected " #expr); \
        }                                                                   \
    } while (false)

#define PM_CHECK_EQ(actual, expected)                                       \
    ::pmtest::check_equal(__FILE__, __LINE__, #actual, #expected, (actual), (expected))
