load("@build_bazel_rules_apple//apple:macos.bzl", "macos_kernel_extension")
load("//:version.bzl", "SANTA_VERSION")

cc_library(
    name = "santa-driver_lib",
    srcs = [
        "SantaCache.h",
        "SantaDecisionManager.cc",
        "SantaDecisionManager.h",
        "SantaDriver.cc",
        "SantaDriver.h",
        "SantaDriverClient.cc",
        "SantaDriverClient.h",
        "SantaPrefixTree.cc",
        "SantaPrefixTree.h",
        "main.cc",
    ],
    copts = [
        "-mkernel",
        "-fapple-kext",
        "-ISource/common",
        "-I__BAZEL_XCODE_SDKROOT__/System/Library/Frameworks/Kernel.framework/PrivateHeaders",
        "-I__BAZEL_XCODE_SDKROOT__/System/Library/Frameworks/Kernel.framework/Headers",
    ],
    defines = [
        "KERNEL",
        "KERNEL_PRIVATE",
        "DRIVER_PRIVATE",
        "APPLE",
        "NeXT",
        "SANTA_VERSION=" + SANTA_VERSION,
    ],
    deps = [
        "//Source/common:SNTKernelCommon",
        "//Source/common:SNTLoggingKernel",
    ],
    alwayslink = 1,
)

# Full santa-driver.kext containing all Santa components
macos_kernel_extension(
    name = "santa-driver",
    additional_contents = {
        "//Source/santabs": "XPCServices",
        "//Source/SantaGUI": "Resources",
        "//Source/santactl": "MacOS",
        "//Source/santad": "MacOS",
    },
    bundle_id = "com.google.santa-driver",
    infoplists = ["Resources/santa-driver-Info.plist"],
    minimum_os_version = "10.9",
    version = "//:version",
    visibility = ["//visibility:public"],
    deps = [":santa-driver_lib"],
)

# A minimal santa-driver.kext, no other Santa components
macos_kernel_extension(
    name = "santa-driver_min",
    bundle_id = "com.google.santa-driver",
    infoplists = ["Resources/santa-driver-Info.plist"],
    minimum_os_version = "10.9",
    version = "//:version",
    visibility = ["//visibility:public"],
    deps = [":santa-driver_lib"],
)
