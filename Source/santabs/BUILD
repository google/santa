load("@build_bazel_rules_apple//apple:macos.bzl", "macos_xpc_service")

objc_library(
    name = "santabs_lib",
    srcs = [
        "SNTBundleService.h",
        "SNTBundleService.m",
        "main.m",
    ],
    deps = [
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTXPCBundleServiceInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "@FMDB",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

macos_xpc_service(
    name = "santabs",
    bundle_id = "com.google.santabs",
    infoplists = ["Resources/santabs-Info.plist"],
    minimum_os_version = "10.9",
    version = "//:version",
    visibility = ["//visibility:public"],
    deps = [":santabs_lib"],
)
