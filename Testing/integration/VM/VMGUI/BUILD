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

macos_application(
    name = "VMGUI",
    bundle_id = "com.google.santa.e2e.vmgui",
    entitlements = "//Testing/integration/VM/Common:entitlements",
    infoplists = ["//Testing/integration/VM/Common:plist"],
    minimum_os_version = "13.0",
    deps = [
        ":vmgui_lib",
    ],
)
