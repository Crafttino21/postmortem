#include <cstdio>
#include <string>
#include <vector>

#include "check.hpp"

namespace pmtest {
namespace {

// Failures are buffered rather than printed as they happen so that each test's
// diagnostics appear underneath its own result line.
std::vector<std::string> g_pending_failures;
int g_total_failures = 0;

}  // namespace

std::vector<TestCase>& registry() {
    // Function-local so registration order across translation units is safe.
    static std::vector<TestCase> tests;
    return tests;
}

Registrar::Registrar(const char* name, TestFn fn) {
    registry().push_back(TestCase{name, fn});
}

void record_failure(const char* file, int line, const std::string& message) {
    ++g_total_failures;
    g_pending_failures.push_back(std::string(file) + ":" + std::to_string(line) + ": " + message);
}

namespace {

int run_all(const char* filter) {
    int selected = 0;
    int failed_tests = 0;

    for (const TestCase& test : registry()) {
        if (filter != nullptr && test.name.find(filter) == std::string::npos) continue;
        ++selected;

        g_pending_failures.clear();
        test.fn();

        const bool passed = g_pending_failures.empty();
        if (!passed) ++failed_tests;

        std::printf("  %-4s %s\n", passed ? "ok" : "FAIL", test.name.c_str());
        for (const std::string& failure : g_pending_failures) {
            std::printf("       %s\n", failure.c_str());
        }
    }

    std::printf("\n%d test%s, %d failed, %d check failure%s\n", selected,
                selected == 1 ? "" : "s", failed_tests, g_total_failures,
                g_total_failures == 1 ? "" : "s");

    if (selected == 0) {
        std::printf("no tests matched the filter\n");
        return 1;
    }
    return failed_tests == 0 ? 0 : 1;
}

}  // namespace
}  // namespace pmtest

int main(int argc, char** argv) {
    // Optional substring filter, so one case can be re-run while debugging:
    //   postmortem_tests signature
    const char* filter = argc > 1 ? argv[1] : nullptr;
    return pmtest::run_all(filter);
}
