load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")

licenses(["notice"])

package(default_visibility = ["//:santa_package_group"])

objc_library(
    name = "FCM_lib",
    srcs = ["SNTCommandSyncFCM.m"],
    hdrs = ["SNTCommandSyncFCM.h"],
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
        "SNTCommandSyncConstants.h",
        "SNTCommandSyncConstants.m",
        "SNTCommandSyncEventUpload.h",
        "SNTCommandSyncEventUpload.m",
        "SNTCommandSyncManager.m",
        "SNTCommandSyncPostflight.h",
        "SNTCommandSyncPostflight.m",
        "SNTCommandSyncPreflight.h",
        "SNTCommandSyncPreflight.m",
        "SNTCommandSyncRuleDownload.h",
        "SNTCommandSyncRuleDownload.m",
        "SNTCommandSyncStage.h",
        "SNTCommandSyncStage.m",
        "SNTCommandSyncState.h",
        "SNTCommandSyncState.m",
    ],
    hdrs = ["SNTCommandSyncManager.h"],
    sdk_frameworks = ["SystemConfiguration"],
    deps = [
        ":FCM_lib",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCSyncdInterface",
        "@MOLAuthenticatingURLSession",
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
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCSyncServiceInterface",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

macos_command_line_application(
    name = "santasyncservice",
    bundle_id = "com.google.santa.syncservice",
    infoplists = ["Info.plist"],
    minimum_os_version = "10.9",
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":santass_lib"],
)
