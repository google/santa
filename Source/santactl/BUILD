load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")
load("//:helper.bzl", "santa_unit_test")

licenses(["notice"])

package(
    default_visibility = ["//:santa_package_group"],
)

objc_library(
    name = "santactl_lib",
    srcs = [
        "SNTCommand.h",
        "SNTCommand.m",
        "SNTCommandController.h",
        "SNTCommandController.m",
        "main.m",
        "Commands/SNTCommandFileInfo.m",
        "Commands/SNTCommandRule.m",
        "Commands/SNTCommandStatus.m",
        "Commands/SNTCommandVersion.m",
        "Commands/SNTCommandMetrics.h",
        "Commands/SNTCommandMetrics.m",
        "Commands/SNTCommandSync.m",
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
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommon",
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
    minimum_os_version = "10.15",
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
