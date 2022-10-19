load(
    "@build_bazel_rules_apple//apple:macos.bzl",
    "macos_command_line_application",
)

objc_library(
    name = "configuration_helper",
    srcs = [
        "MacOSVirtualMachineConfigurationHelper.m",
    ],
    hdrs = [
        "MacOSVirtualMachineConfigurationHelper.h",
    ],
    sdk_frameworks = [
        "Virtualization",
    ],
)

objc_library(
    name = "vmcli_lib",
    srcs = [
        "main.m",
    ],
    sdk_frameworks = [
        "Virtualization",
    ],
    deps = [
        ":configuration_helper",
    ],
)

filegroup(
    name = "entitlements",
    srcs = [
        "VMCLI.entitlements",
    ],
)

macos_command_line_application(
    name = "VMCLI",
    codesignopts = [
        "--entitlements=Testing/integration/VMCLI/VMCLI.entitlements",
    ],
    minimum_os_version = "12.0",
    deps = [
        ":entitlements",
        ":vmcli_lib",
    ],
)
