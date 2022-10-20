load(
    "@build_bazel_rules_apple//apple:macos.bzl",
    "macos_command_line_application",
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
        "//Testing/integration/VM/Common:configuration_helper",
        "//Testing/integration/VM/Common:error",
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
        "--entitlements=Testing/integration/VM/VMCLI/VMCLI.entitlements",
    ],
    minimum_os_version = "12.0",
    deps = [
        ":entitlements",
        ":vmcli_lib",
    ],
)
