package(
    default_visibility = [
        "//Testing/integration/VM:__subpackages__",
    ],
    features = ["-layering_check"],
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
    name = "delegate",
    srcs = [
        "MacOSVirtualMachineDelegate.m",
    ],
    hdrs = [
        "MacOSVirtualMachineDelegate.h",
    ],
    sdk_frameworks = [
        "Virtualization",
    ],
)

objc_library(
    name = "error",
    hdrs = [
        "Error.h",
    ],
)

filegroup(
    name = "entitlements",
    srcs = [
        "VM.entitlements",
    ],
)

filegroup(
    name = "plist",
    srcs = [
        "Info.plist",
    ],
)
