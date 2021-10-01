load("//:helper.bzl", "santa_unit_test")

licenses(["notice"])

santa_unit_test(
    name = "SNTExecTest",
    data = [
        "//Source/santad/testdata:binaryrules_testdata",
    ],
    srcs = [
        "SNTExecTest.m"
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
