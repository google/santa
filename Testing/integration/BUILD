load("//:helper.bzl", "santa_unit_test")
load(
    "@build_bazel_rules_apple//apple:macos.bzl",
    "macos_command_line_application",
)

package(default_visibility = ["//:santa_package_group"])

licenses(["notice"])

santa_unit_test(
    name = "SNTExecTest",
    srcs = [
        "SNTExecTest.m",
    ],
    data = [
        "//Source/santad/testdata:binaryrules_testdata",
    ],
    minimum_os_version = "10.15",
    deps = [],
)

test_suite(
    name = "integration_tests",
    tests = [
        ":SNTExecTest",
    ],
)

objc_library(
    name = "santa_logging_benchmarks_lib",
    srcs = [
        "SNTLoggingBenchmarks.m",
    ],
    deps = [
        "//Source/santad:santad_event_logs",
    ],

)

macos_command_line_application(
    name = "santa_logging_benchmarks_bin",
    bundle_id = "com.goole.santa.benchmark.logging",
    minimum_os_version = "10.15",
    deps = [":santa_logging_benchmarks_lib"],
)
