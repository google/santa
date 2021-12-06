load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")
load("//:helper.bzl", "santa_unit_test")

licenses(["notice"])

package(default_visibility = ["//:santa_package_group"])

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
        "Commands/sync/NSData+Zlib.h",
        "Commands/sync/NSData+Zlib.m",
        "Commands/sync/SNTCommandSync.m",
        "Commands/sync/SNTCommandSyncConstants.h",
        "Commands/sync/SNTCommandSyncConstants.m",
        "Commands/sync/SNTCommandSyncEventUpload.h",
        "Commands/sync/SNTCommandSyncEventUpload.m",
        "Commands/sync/SNTCommandSyncManager.h",
        "Commands/sync/SNTCommandSyncManager.m",
        "Commands/sync/SNTCommandSyncPostflight.h",
        "Commands/sync/SNTCommandSyncPostflight.m",
        "Commands/sync/SNTCommandSyncPreflight.h",
        "Commands/sync/SNTCommandSyncPreflight.m",
        "Commands/sync/SNTCommandSyncRuleDownload.h",
        "Commands/sync/SNTCommandSyncRuleDownload.m",
        "Commands/sync/SNTCommandSyncStage.h",
        "Commands/sync/SNTCommandSyncStage.m",
        "Commands/sync/SNTCommandSyncState.h",
        "Commands/sync/SNTCommandSyncState.m",
    ] + select({
        "//:opt_build": [],
        "//conditions:default": [
            "Commands/SNTCommandBundleInfo.m",
            "Commands/SNTCommandCacheHistogram.m",
            "Commands/SNTCommandCheckCache.m",
            "Commands/SNTCommandFlushCache.m",
        ],
    }),
    sdk_dylibs = ["libz"],
    sdk_frameworks = ["IOKit"],
    deps = [
        ":FCM_lib",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTKernelCommon",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTSystemInfo",
        "//Source/common:SNTXPCBundleServiceInterface",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncdInterface",
        "//Source/common:SNTXPCUnprivilegedControlInterface",
        "@FMDB",
        "@MOLAuthenticatingURLSession",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "FCM_lib",
    srcs = ["Commands/sync/SNTCommandSyncFCM.m"],
    hdrs = ["Commands/sync/SNTCommandSyncFCM.h"],
    sdk_frameworks = ["SystemConfiguration"],
    deps = [
        "@MOLAuthenticatingURLSession",
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
    minimum_os_version = "10.9",
    provisioning_profile = select({
        "//:ci_build": None,
        "//conditions:default": "Santa_Dev.provisionprofile",
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
        "//Source/common:SNTXPCControlInterface",
        "@MOLCertificate",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTCommandSyncTest",
    srcs = [
        "Commands/sync/NSData+Zlib.h",
        "Commands/sync/NSData+Zlib.m",
        "Commands/sync/SNTCommandSync.m",
        "Commands/sync/SNTCommandSyncConstants.h",
        "Commands/sync/SNTCommandSyncConstants.m",
        "Commands/sync/SNTCommandSyncEventUpload.h",
        "Commands/sync/SNTCommandSyncEventUpload.m",
        "Commands/sync/SNTCommandSyncManager.h",
        "Commands/sync/SNTCommandSyncManager.m",
        "Commands/sync/SNTCommandSyncPostflight.h",
        "Commands/sync/SNTCommandSyncPostflight.m",
        "Commands/sync/SNTCommandSyncPreflight.h",
        "Commands/sync/SNTCommandSyncPreflight.m",
        "Commands/sync/SNTCommandSyncRuleDownload.h",
        "Commands/sync/SNTCommandSyncRuleDownload.m",
        "Commands/sync/SNTCommandSyncStage.h",
        "Commands/sync/SNTCommandSyncStage.m",
        "Commands/sync/SNTCommandSyncState.h",
        "Commands/sync/SNTCommandSyncState.m",
        "Commands/sync/SNTCommandSyncTest.m",
        "SNTCommand.h",
        "SNTCommand.m",
        "SNTCommandController.h",
        "SNTCommandController.m",
    ],
    resources = glob([
        "Commands/sync/testdata/*.json",
        "Commands/sync/testdata/*.plist",
    ]),
    sdk_dylibs = ["libz"],
    deps = [
        ":FCM_lib",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncdInterface",
        "@MOLAuthenticatingURLSession",
        "@MOLXPCConnection",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTCommandMetricsTest",
    srcs = ["Commands/SNTCommandMetricsTest.m"],
    structured_resources = glob(["Commands/testdata/*"]),
    visibility = ["//:santa_package_group"],
    deps = [
        ":santactl_lib",
        "//Source/santametricservice/Formats:SNTMetricFormatTestHelper",
        "@OCMock",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTCommandFileInfoTest",
        ":SNTCommandMetricsTest",
        ":SNTCommandSyncTest",
    ],
    visibility = ["//:santa_package_group"],
)
