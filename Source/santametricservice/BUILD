load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")
load("//:helper.bzl", "santa_unit_test")

package(default_visibility = ["//:santa_package_group"])

licenses(["notice"])  # Apache 2.0

objc_library(
    name = "SNTMetricServiceLib",
    srcs = [
        "SNTMetricService.h",
        "SNTMetricService.m",
	"main.m",
    ],
    deps = [
        "//Source/common:SNTXPCMetricServiceInterface",
        "//Source/common:SNTLogging",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTMetricSet",
        "//Source/santametricservice/Formats:SNTMetricRawJsonFormat",
        "//Source/santametricservice/Writers:SNTMetricFileWriter",
     	"@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

santa_unit_test(
    name="SNTMetricServiceTest",
    srcs = ["SNTMetricServiceTest.m"],
    deps = [
	":SNTMetricServiceLib",
	"@OCMock",
    ],
)

test_suite(
    name="unit_tests",
    tests = [
      ":SNTMetricServiceTest",
      "//Source/santametricservice/Formats:SNTMetricRawJsonFormatTest",
      "//Source/santametricservice/Writers:SNTMetricFileWriterTest",
    ],
)


macos_command_line_application(
    name = "santametricservice",
    bundle_id = "com.google.santa.metricservice",
    infoplists = ["Info.plist"],
    minimum_os_version = "10.15",
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":SNTMetricServiceLib"],
)
