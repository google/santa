load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
    features = ["-layering_check"],
)

licenses(["notice"])

objc_library(
    name = "SNTMetricServiceLib",
    srcs = [
        "SNTMetricService.h",
        "SNTMetricService.m",
        "main.m",
    ],
    hdrs = [
        "SNTMetricService.h",
    ],
    deps = [
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTXPCMetricServiceInterface",
        "//Source/santametricservice/Formats:SNTMetricMonarchJSONFormat",
        "//Source/santametricservice/Formats:SNTMetricRawJSONFormat",
        "//Source/santametricservice/Writers:SNTMetricFileWriter",
        "//Source/santametricservice/Writers:SNTMetricHTTPWriter",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

santa_unit_test(
    name = "SNTMetricServiceTest",
    srcs = ["SNTMetricServiceTest.m"],
    structured_resources = ["//Source/santametricservice/Formats:testdata"],
    deps = [
        ":SNTMetricServiceLib",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTMetricSet",
        "//Source/santametricservice/Formats:SNTMetricFormatTestHelper",
        "@MOLAuthenticatingURLSession",
        "@OCMock",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTMetricServiceTest",
        "//Source/santametricservice/Formats:format_tests",
        "//Source/santametricservice/Writers:writer_tests",
    ],
)

macos_command_line_application(
    name = "santametricservice",
    bundle_id = "com.google.santa.metricservice",
    codesignopts = [
        "--timestamp",
        "--force",
        "--options library,kill,runtime",
    ],
    infoplists = ["Info.plist"],
    minimum_os_version = "11.0",
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "//profiles:santa_dev",
    }),
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [
        ":SNTMetricServiceLib",
    ],
)
