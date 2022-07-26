load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")
load("//:helper.bzl", "santa_unit_test")

licenses(["notice"])

package(
    default_visibility = ["//:santa_package_group"],
)

objc_library(
    name = "FCM_lib",
    srcs = ["SNTSyncFCM.m"],
    hdrs = ["SNTSyncFCM.h"],
    sdk_frameworks = ["SystemConfiguration"],
    deps = [
        "@MOLAuthenticatingURLSession",
    ],
)

objc_library(
    name = "sync_lib",
    srcs = [
        "NSData+Zlib.h",
        "NSData+Zlib.m",
        "SNTPushNotifications.h",
        "SNTPushNotifications.m",
        "SNTPushNotificationsTracker.h",
        "SNTPushNotificationsTracker.m",
        "SNTSyncEventUpload.h",
        "SNTSyncEventUpload.m",
        "SNTSyncLogging.h",
        "SNTSyncLogging.m",
        "SNTSyncManager.m",
        "SNTSyncPostflight.h",
        "SNTSyncPostflight.m",
        "SNTSyncPreflight.h",
        "SNTSyncPreflight.m",
        "SNTSyncRuleDownload.h",
        "SNTSyncRuleDownload.m",
        "SNTSyncStage.h",
        "SNTSyncStage.m",
        "SNTSyncState.h",
        "SNTSyncState.m",
    ],
    hdrs = ["SNTSyncManager.h"],
    sdk_dylibs = ["libz"],
    deps = [
        ":FCM_lib",
        ":broadcaster_lib",
        "//Source/common:SNTCommon",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTSyncConstants",
        "//Source/common:SNTSystemInfo",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "@MOLAuthenticatingURLSession",
        "@MOLCertificate",
        "@MOLXPCConnection",
    ],
)

# Using :sync_lib breaks the Zlib category hack used in the tests to
# disable compression, in turn failing the tests. Re-compile here to keep
# the "override" category behavior.
santa_unit_test(
    name = "SNTSyncTest",
    srcs = [
        "NSData+Zlib.h",
        "NSData+Zlib.m",
        "SNTPushNotifications.h",
        "SNTPushNotifications.m",
        "SNTPushNotificationsTracker.h",
        "SNTPushNotificationsTracker.m",
        "SNTSyncEventUpload.h",
        "SNTSyncEventUpload.m",
        "SNTSyncLogging.h",
        "SNTSyncLogging.m",
        "SNTSyncPostflight.h",
        "SNTSyncPostflight.m",
        "SNTSyncPreflight.h",
        "SNTSyncPreflight.m",
        "SNTSyncRuleDownload.h",
        "SNTSyncRuleDownload.m",
        "SNTSyncStage.h",
        "SNTSyncStage.m",
        "SNTSyncState.h",
        "SNTSyncState.m",
        "SNTSyncTest.m",
    ],
    resources = glob([
        "testdata/*.json",
        "testdata/*.plist",
    ]),
    sdk_dylibs = ["libz"],
    deps = [
        ":FCM_lib",
        ":broadcaster_lib",
        "//Source/common:SNTCommon",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTSyncConstants",
        "//Source/common:SNTSystemInfo",
        "//Source/common:SNTXPCControlInterface",
        "@MOLAuthenticatingURLSession",
        "@MOLCertificate",
        "@MOLXPCConnection",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "NSDataZlibTest",
    srcs = [
        "NSData+Zlib.h",
        "NSData+Zlib.m",
        "NSDataZlibTest.m",
    ],
    resources = glob(["testdata/sync_preflight_basic.*"]),
    sdk_dylibs = ["libz"],
)

objc_library(
    name = "broadcaster_lib",
    srcs = ["SNTSyncBroadcaster.m"],
    hdrs = ["SNTSyncBroadcaster.h"],
    deps = [
        "//Source/common:SNTXPCSyncServiceInterface",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "santass_lib",
    srcs = [
        "SNTSyncService.h",
        "SNTSyncService.m",
        "main.m",
    ],
    deps = [
        ":broadcaster_lib",
        ":sync_lib",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

macos_command_line_application(
    name = "santasyncservice",
    bundle_id = "com.google.santa.syncservice",
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
    visibility = ["//:santa_package_group"],
    deps = [":santass_lib"],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":NSDataZlibTest",
        ":SNTSyncTest",
    ],
    visibility = ["//:santa_package_group"],
)
