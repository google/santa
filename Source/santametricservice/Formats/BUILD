load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
    features = ["-layering_check"],
)

licenses(["notice"])

objc_library(
    name = "SNTMetricFormat",
    hdrs = ["SNTMetricFormat.h"],
)

objc_library(
    name = "SNTMetricFormatTestHelper",
    srcs = [
        "SNTMetricFormatTestHelper.m",
    ],
    hdrs = ["SNTMetricFormatTestHelper.h"],
    deps = [
        "//Source/common:SNTMetricSet",
    ],
)

objc_library(
    name = "SNTMetricRawJSONFormat",
    srcs = [
        "SNTMetricFormat.h",
        "SNTMetricRawJSONFormat.h",
        "SNTMetricRawJSONFormat.m",
    ],
    deps = [
        ":SNTMetricFormat",
        "//Source/common:SNTLogging",
    ],
)

objc_library(
    name = "SNTMetricMonarchJSONFormat",
    srcs = [
        "SNTMetricFormat.h",
        "SNTMetricMonarchJSONFormat.h",
        "SNTMetricMonarchJSONFormat.m",
    ],
    deps = [
        ":SNTMetricFormat",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
    ],
)

santa_unit_test(
    name = "SNTMetricRawJSONFormatTest",
    srcs = [
        "SNTMetricRawJSONFormatTest.m",
    ],
    structured_resources = glob(["testdata/**"]),
    deps = [
        ":SNTMetricFormatTestHelper",
        ":SNTMetricRawJSONFormat",
    ],
)

santa_unit_test(
    name = "SNTMetricMonarchJSONFormatTest",
    srcs = [
        "SNTMetricMonarchJSONFormatTest.m",
    ],
    structured_resources = [":testdata"],
    deps = [
        ":SNTMetricFormatTestHelper",
        ":SNTMetricMonarchJSONFormat",
    ],
)

filegroup(
    name = "testdata",
    srcs = glob(["testdata/**"]),
)

test_suite(
    name = "format_tests",
    tests = [
        ":SNTMetricMonarchJSONFormatTest",
        ":SNTMetricRawJSONFormatTest",
    ],
)
