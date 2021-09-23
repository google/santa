load("//:helper.bzl", "santa_unit_test")

package(default_visibility = ["//:santa_package_group"])

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

test_suite(
    name = "format_tests",
    tests = [
        ":SNTMetricRawJSONFormatTest",
    ],
)
