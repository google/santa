load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")
load("//:helper.bzl", "santa_unit_test")

licenses(["notice"])

package(
    default_visibility = ["//:santa_package_group"],
)

objc_library(
    name = "santactl_cmd",
    srcs = [
        "SNTCommand.m",
        "SNTCommandController.m",
    ],
    hdrs = [
        "SNTCommand.h",
        "SNTCommandController.h",
    ],
    deps = [
        "//Source/common:SNTXPCControlInterface",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "SNTCommandPrintLog",
    srcs = ["Commands/SNTCommandPrintLog.mm"],
    deps = [
        ":santactl_cmd",
        "//Source/common:SNTLogging",
        "//Source/common:santa_cc_proto_library_wrapper",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:binaryproto_cc_proto_library_wrapper",
        "@com_google_protobuf//src/google/protobuf/json",
    ],
)

objc_library(
    name = "santactl_lib",
    srcs = [
        "Commands/SNTCommandFileInfo.m",
        "Commands/SNTCommandMetrics.h",
        "Commands/SNTCommandMetrics.m",
        "Commands/SNTCommandRule.m",
        "Commands/SNTCommandStatus.m",
        "Commands/SNTCommandSync.m",
        "Commands/SNTCommandVersion.m",
        "main.m",
    ] + select({
        "//:opt_build": [],
        "//conditions:default": [
            "Commands/SNTCommandBundleInfo.m",
            "Commands/SNTCommandCheckCache.m",
            "Commands/SNTCommandFlushCache.m",
        ],
    }),
    sdk_dylibs = ["libz"],
    sdk_frameworks = ["IOKit"],
    deps = [
        ":SNTCommandPrintLog",
        ":santactl_cmd",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTSystemInfo",
        "//Source/common:SNTXPCBundleServiceInterface",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "//Source/common:SNTXPCUnprivilegedControlInterface",
        "//Source/santasyncservice:sync_lib",
        "@FMDB",
        "@MOLCertificate",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

macos_command_line_application(
    name = "santactl",
    bundle_id = "com.google.santa.ctl",
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
    deps = [":santactl_lib"],
)

santa_unit_test(
    name = "SNTCommandFileInfoTest",
    srcs = [
        "Commands/SNTCommandFileInfo.m",
        "Commands/SNTCommandFileInfoTest.m",
        "SNTCommand.h",
        "SNTCommand.m",
        "SNTCommandController.h",
        "SNTCommandController.m",
    ],
    deps = [
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTXPCControlInterface",
        "@MOLCertificate",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTCommandMetricsTest",
    srcs = [
        "Commands/SNTCommandMetrics.h",
        "Commands/SNTCommandMetricsTest.m",
        "SNTCommand.h",
        "SNTCommandController.h",
    ],
    structured_resources = glob(["Commands/testdata/*"]),
    visibility = ["//:santa_package_group"],
    deps = [
        ":santactl_lib",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTXPCControlInterface",
        "//Source/santametricservice/Formats:SNTMetricFormatTestHelper",
        "@MOLXPCConnection",
        "@OCMock",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTCommandFileInfoTest",
        ":SNTCommandMetricsTest",
    ],
    visibility = ["//:santa_package_group"],
)
