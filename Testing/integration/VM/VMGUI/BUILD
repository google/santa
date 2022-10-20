load(
    "@build_bazel_rules_apple//apple:macos.bzl",
    "macos_application",
)

objc_library(
    name = "vmgui_lib",
    srcs = [
        "AppDelegate.m",
        "main.m",
    ],
    hdrs = [
        "AppDelegate.h",
    ],
    data = [
        "Resources/MainMenu.xib",
    ],
    sdk_frameworks = [
        "Virtualization",
    ],
    deps = [
        "//Testing/integration/VM/Common:configuration_helper",
        "//Testing/integration/VM/Common:delegate",
        "//Testing/integration/VM/Common:error",
    ],
)

filegroup(
    name = "entitlements",
    srcs = [
        "VMGUI.entitlements",
    ],
)

macos_application(
    name = "VMGUI",
    bundle_id = "com.google.santa.e2e.vmgui",
    codesignopts = [
        "--entitlements=Testing/integration/VM/VMGUI/VMGUI.entitlements",
    ],
    infoplists = ["Info.plist"],
    minimum_os_version = "12.0",
    deps = [
        ":entitlements",
        ":vmgui_lib",
    ],
)
