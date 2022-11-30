load("//:helper.bzl", "santa_unit_test")

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
    minimum_os_version = "11.0",
    deps = [],
)

test_suite(
    name = "integration_tests",
    tests = [
        ":SNTExecTest",
    ],
)
