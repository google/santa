load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")
load("//:helper.bzl", "santa_unit_test")

package(default_visibility = ["//:santa_package_group"])

licenses(["notice"])  # Apache 2.0

objc_library(
    name = "SNTMetricFormat",
    hdrs = ["SNTMetricFormat.h"],
)

objc_library(
    name = "SNTMetricRawJsonFormat",
    srcs = [
        "SNTMetricRawJsonFormat.h",
        "SNTMetricRawJsonFormat.m",
    	"SNTMetricFormat.h",

    ],
    deps = [
        ":SNTMetricFormat",
        "//Source/common:SNTLogging",
    ],
)

santa_unit_test(
    name = "SNTMetricRawJsonFormatTest",
    srcs = [
        "SNTMetricRawJsonFormatTest.m",
    ],
    structured_resources = glob(["testdata/**"]),
    deps = [
        ":SNTMetricRawJsonFormat",
	"//Source/common:SNTMetricSet",
    ],
)


test_suite(
   name = "format_tests",
   tests = [
     ":SNTMetricRawJsonFormatTest",
   ],
)
