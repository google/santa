load(
    "@build_bazel_rules_apple//apple:macos.bzl",
    "macos_application",
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

macos_application(
    name = "VMCLI",
    bundle_id = "com.google.santa.e2e.vmcli",
    infoplists = ["//Testing/integration/VM/Common:plist"],
    entitlements = "//Testing/integration/VM/Common:entitlements",
    minimum_os_version = "12.0",
    deps = [
        ":vmcli_lib",
    ],
)
