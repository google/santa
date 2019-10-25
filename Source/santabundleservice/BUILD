licenses(["notice"])  # Apache 2.0

load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")

objc_library(
    name = "santabs_lib",
    srcs = [
        "SNTBundleService.h",
        "SNTBundleService.m",
        "main.m",
    ],
    deps = [
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCBundleServiceInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "@FMDB",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

macos_command_line_application(
    name = "santabundleservice",
    bundle_id = "com.google.santa.bundleservice",
    infoplists = ["Info.plist"],
    minimum_os_version = "10.9",
    version = "//:version",
    visibility = ["//visibility:public"],
    deps = [":santabs_lib"],
)

