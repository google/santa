load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

licenses(["notice"])

objc_library(
    name = "SNTMetricWriter",
    hdrs = ["SNTMetricWriter.h"],
)

objc_library(
    name = "SNTMetricFileWriter",
    srcs = [
        "SNTMetricFileWriter.h",
        "SNTMetricFileWriter.m",
    ],
    hdrs = [
        "SNTMetricFileWriter.h",
    ],
    deps = [
        ":SNTMetricWriter",
        "//Source/common:SNTLogging",
    ],
)

santa_unit_test(
    name = "SNTMetricFileWriterTest",
    srcs = [
        "SNTMetricFileWriterTest.m",
    ],
    deps = [
        ":SNTMetricFileWriter",
    ],
)

objc_library(
    name = "SNTMetricHTTPWriter",
    srcs = [
        "SNTMetricHTTPWriter.h",
        "SNTMetricHTTPWriter.m",
    ],
    hdrs = [
        "SNTMetricHTTPWriter.h",
    ],
    deps = [
        ":SNTMetricWriter",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "@MOLAuthenticatingURLSession",
    ],
)

santa_unit_test(
    name = "SNTMetricHTTPWriterTest",
    srcs = [
        "SNTMetricHTTPWriterTest.m",
    ],
    deps = [
        ":SNTMetricHTTPWriter",
        "@OCMock",
    ],
)

test_suite(
    name = "writer_tests",
    tests = [
        ":SNTMetricFileWriterTest",
        ":SNTMetricHTTPWriterTest",
    ],
)
