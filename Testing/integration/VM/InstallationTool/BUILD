load(
    "@build_bazel_rules_apple//apple:macos.bzl",
    "macos_application",
)

objc_library(
    name = "installationtool_lib",
    srcs = [
        "MacOSRestoreImage.m",
        "MacOSVirtualMachineInstaller.m",
        "main.m",
    ],
    hdrs = [
        "MacOSRestoreImage.h",
        "MacOSVirtualMachineInstaller.h",
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
    name = "InstallationTool",
    bundle_id = "com.google.santa.e2e.installation-tool",
    entitlements = "//Testing/integration/VM/Common:entitlements",
    infoplists = ["//Testing/integration/VM/Common:plist"],
    minimum_os_version = "12.0",
    deps = [
        ":installationtool_lib",
    ],
)
