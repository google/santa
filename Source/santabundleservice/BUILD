load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")

licenses(["notice"])

package(
    default_visibility = ["//:santa_package_group"],
)

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
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTXPCBundleServiceInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:SigningIDHelpers",
        "@FMDB",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

macos_command_line_application(
    name = "santabundleservice",
    bundle_id = "com.google.santa.bundleservice",
    codesignopts = [
        "--timestamp",
        "--force",
        "--options library,kill,runtime",
    ],
    infoplists = ["Info.plist"],
    minimum_os_version = "12.0",
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "//profiles:santa_dev",
    }),
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":santabs_lib"],
)
