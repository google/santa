load("@build_bazel_rules_apple//apple:macos.bzl", "macos_application")

licenses(["notice"])

exports_files([
    "Resources/Images.xcassets/AppIcon.appiconset/santa-hat-icon-256.png",
])

objc_library(
    name = "SantaGUI_lib",
    srcs = [
        "SNTAboutWindowController.h",
        "SNTAboutWindowController.m",
        "SNTAccessibleTextField.h",
        "SNTAccessibleTextField.m",
        "SNTAppDelegate.h",
        "SNTAppDelegate.m",
        "SNTBinaryMessageWindowController.h",
        "SNTBinaryMessageWindowController.m",
        "SNTDeviceMessageWindowController.h",
        "SNTDeviceMessageWindowController.m",
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
        "Resources/DeviceMessageWindow.xib",
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
        "//Source/common:SNTLogging",
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
        "//Source/santametricservice": "MacOS",
        "//Source/santasyncservice": "MacOS",
        "//Source/santad:com.google.santa.daemon": "Library/SystemExtensions",
    },
    app_icons = glob(["Resources/Images.xcassets/**"]),
    bundle_id = "com.google.santa",
    bundle_name = "Santa",
    codesignopts = [
        "--timestamp",
        "--force",
        "--options library,kill,runtime",
    ],
    entitlements = "Santa.app.entitlements",
    infoplists = ["Info.plist"],
    minimum_os_version = "10.15",
    provisioning_profile = select({
        "//:ci_build": None,
        "//conditions:default": "//profiles:santa_dev",
    }),
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":SantaGUI_lib"],
)
