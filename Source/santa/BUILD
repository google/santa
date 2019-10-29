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
    data = [
        "Resources/AboutWindow.xib",
        "Resources/MessageWindow.xib",
    ],
    sdk_frameworks = [
        "IOKit",
        "SecurityInterface",
        "SystemExtensions",
    ],
    deps = [
        "//Source/common:SNTBlockMessage_SantaGUI",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

macos_application(
    name = "Santa",
    additional_contents = {
        "//Source/santactl": "MacOS",
        "//Source/santabundleservice": "MacOS",
        "//Source/santad:com.google.santa.daemon": "Library/SystemExtensions",
    },
    app_icons = glob(["Resources/Images.xcassets/**"]),
    bundle_id = "com.google.santa",
    bundle_name = "Santa",
    infoplists = ["Resources/santa-Info.plist"],
    ipa_post_processor = "postprocess.sh",
    minimum_os_version = "10.9",
    version = "//:version",
    visibility = ["//visibility:public"],
    deps = [":SantaGUI_lib"],
)
