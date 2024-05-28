load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("//:helper.bzl", "santa_unit_test")

licenses(["notice"])

package(
    default_visibility = ["//:santa_package_group"],
)

proto_library(
    name = "sync_v1_proto",
    srcs = ["syncv1.proto"],
)

cc_proto_library(
    name = "sync_v1_cc_proto",
    deps = [":sync_v1_proto"],
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
        "SNTSyncEventUpload.mm",
        "SNTSyncLogging.h",
        "SNTSyncLogging.m",
        "SNTSyncManager.m",
        "SNTSyncPostflight.h",
        "SNTSyncPostflight.mm",
        "SNTSyncPreflight.h",
        "SNTSyncPreflight.mm",
        "SNTSyncRuleDownload.h",
        "SNTSyncRuleDownload.mm",
        "SNTSyncStage.h",
        "SNTSyncStage.mm",
        "SNTSyncState.h",
        "SNTSyncState.m",
    ],
    hdrs = ["SNTSyncManager.h"],
    sdk_dylibs = ["libz"],
    deps = [
        ":FCM_lib",
        ":broadcaster_lib",
        ":sync_v1_cc_proto",
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
        "//Source/common:String",
        "@MOLAuthenticatingURLSession",
        "@MOLCertificate",
        "@MOLXPCConnection",
        "@com_google_protobuf//src/google/protobuf/json",
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
        "SNTSyncEventUpload.mm",
        "SNTSyncLogging.h",
        "SNTSyncLogging.m",
        "SNTSyncPostflight.h",
        "SNTSyncPostflight.mm",
        "SNTSyncPreflight.h",
        "SNTSyncPreflight.mm",
        "SNTSyncRuleDownload.h",
        "SNTSyncRuleDownload.mm",
        "SNTSyncStage.h",
        "SNTSyncStage.mm",
        "SNTSyncState.h",
        "SNTSyncState.m",
        "SNTSyncTest.mm",
    ],
    resources = glob([
        "testdata/*.json",
        "testdata/*.plist",
    ]),
    sdk_dylibs = ["libz"],
    deps = [
        ":FCM_lib",
        ":broadcaster_lib",
        ":sync_v1_cc_proto",
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
        "//Source/common:String",
        "@MOLAuthenticatingURLSession",
        "@MOLCertificate",
        "@MOLXPCConnection",
        "@OCMock",
        "@com_google_protobuf//src/google/protobuf/json",
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
    minimum_os_version = "11.0",
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
