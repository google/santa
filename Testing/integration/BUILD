load("@build_bazel_rules_apple//apple:macos.bzl", "macos_bundle")
load("//:helper.bzl", "santa_unit_test")

santa_unit_test(
    name = "SNTExecTest",
    data = [
        "//Source/santad/testdata:binaryrules_testdata",
    ],
    srcs = [
        "SNTBenchmarkTest.m"
    ],
    deps = [],
    minimum_os_version = "10.15",
)

test_suite(
    name = "integration_tests",
    tests = [
        ":SNTExecTest",
    ],
)
