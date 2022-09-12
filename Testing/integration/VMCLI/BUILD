load(
    "@build_bazel_rules_apple//apple:macos.bzl",
    "macos_command_line_application",
)

objc_library(
    name = "configuration_helper",
    hdrs = [
        "MacOSVirtualMachineConfigurationHelper.h",
    ],
    srcs = [
        "MacOSVirtualMachineConfigurationHelper.m",
    ],
    sdk_frameworks = [
        "Virtualization",
    ]
)

objc_library(
    name = "vmcli_lib",
    srcs = [
        "main.m",
    ],
    deps = [
        ":configuration_helper",
    ],
    sdk_frameworks = [
        "Virtualization",
    ]
)

filegroup(
  name = "entitlements",
  srcs = [
    "VMCLI.entitlements"
  ]
)

macos_command_line_application(
    name = "VMCLI",
    codesign_inputs = [
      ":entitlements",
    ],
    codesignopts = [
      "--entitlements=Testing/integration/VMCLI/VMCLI.entitlements",
    ],
    deps = [":vmcli_lib"],
    minimum_os_version = "12.0",
)
