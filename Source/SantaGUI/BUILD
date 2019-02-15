licenses(["notice"])  # Apache 2.0

exports_files([
    "Resources/Images.xcassets/AppIcon.appiconset/santa-hat-icon-256.png",
])

load("@build_bazel_rules_apple//apple:macos.bzl", "macos_application")

objc_library(
    name = "SantaGUI_lib",
    srcs = [
        "SNTAboutWindowController.h",
        "SNTAboutWindowController.m",
        "SNTAccessibleTextField.h",
        "SNTAccessibleTextField.m",
        "SNTAppDelegate.h",
        "SNTAppDelegate.m",
        "SNTMessageWindow.h",
        "SNTMessageWindow.m",
        "SNTMessageWindowController.h",
        "SNTMessageWindowController.m",
        "SNTNotificationManager.h",
        "SNTNotificationManager.m",
        "main.m",
    ],
    sdk_frameworks = [
        "IOKit",
        "SecurityInterface",
    ],
    xibs = [
        "Resources/AboutWindow.xib",
        "Resources/MessageWindow.xib",
    ],
    deps = [
        "//Source/common:SNTBlockMessage",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

macos_application(
    name = "SantaGUI",
    app_icons = glob(["Resources/Images.xcassets/**"]),
    bundle_id = "com.google.SantaGUI",
    bundle_name = "Santa",
    infoplists = ["Resources/SantaGUI-Info.plist"],
    minimum_os_version = "10.9",
    version = "//:version",
    visibility = ["//visibility:public"],
    deps = [":SantaGUI_lib"],
)
