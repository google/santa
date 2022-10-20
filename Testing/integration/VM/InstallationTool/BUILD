load(
    "@build_bazel_rules_apple//apple:macos.bzl",
    "macos_command_line_application",
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

filegroup(
    name = "entitlements",
    srcs = [
        "InstallationTool.entitlements",
    ],
)

macos_command_line_application(
    name = "InstallationTool",
    codesignopts = [
        "--entitlements=Testing/integration/VM/InstallationTool/InstallationTool.entitlements",
    ],
    minimum_os_version = "12.0",
    deps = [
        ":entitlements",
        ":installationtool_lib",
    ],
)
