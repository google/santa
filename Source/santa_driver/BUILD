licenses(["notice"])  # Apache 2.0

load(
    "@build_bazel_rules_apple//apple:macos.bzl",
    "macos_command_line_application",
    "macos_kernel_extension",
)
load("//:helper.bzl", "run_command", "santa_unit_test")
load("//:version.bzl", "SANTA_VERSION")

cc_library(
    name = "santa_driver_lib",
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

santa_unit_test(
    name = "SantaCacheTest",
    srcs = [
        "SantaCache.h",
        "SantaCacheTest.mm",
    ],
    deps = ["//Source/common:SNTKernelCommon"],
)

santa_unit_test(
    name = "SantaPrefixTreeTest",
    srcs = [
        "SantaPrefixTree.cc",
        "SantaPrefixTree.h",
        "SantaPrefixTreeTest.mm",
    ],
    copts = ["-std=c++1z"],
    deps = ["//Source/common:SNTKernelCommon"],
)

# Full santa-driver.kext containing all Santa components
macos_kernel_extension(
    name = "santa_driver",
    additional_contents = {
        "//Source/santabs": "XPCServices",
        "//Source/SantaGUI": "Resources",
        "//Source/santactl": "MacOS",
        "//Source/santad": "MacOS",
    },
    bundle_id = "com.google.santa-driver",
    bundle_name = "santa-driver",
    infoplists = ["Info.plist"],
    minimum_os_version = "10.9",
    version = "//:version",
    visibility = ["//visibility:public"],
    deps = [":santa_driver_lib"],
)

# A minimal santa-driver.kext, no other Santa components
macos_kernel_extension(
    name = "santa_driver_min",
    bundle_id = "com.google.santa-driver",
    bundle_name = "santa-driver",
    infoplists = ["Info.plist"],
    minimum_os_version = "10.9",
    version = "//:version",
    visibility = ["//visibility:public"],
    deps = [":santa_driver_lib"],
)

objc_library(
    name = "kernel_tests_lib",
    srcs = ["kernel_tests.mm"],
    sdk_frameworks = [
        "Foundation",
        "IOKit",
    ],
    deps = ["//Source/common:SNTKernelCommon"],
)

macos_command_line_application(
    name = "kernel_tests_bin",
    bundle_id = "com.google.santa.KernelTests",
    minimum_os_version = "10.9",
    deps = [":kernel_tests_lib"],
)

run_command(
    name = "kernel_tests",
    srcs = [
        ":kernel_tests_bin",
        "//Source/santa_driver:santa_driver_min",
    ],
    cmd = """
env
function sigint() {
  echo "\nInterrupted, unloading driver."
  sudo kextunload -b com.google.santa-driver >/dev/null
  exit 1
}
unzip -o $${BUILD_WORKSPACE_DIRECTORY}/bazel-bin/Source/santa_driver/santa-driver.zip >/dev/null
echo "Launching Kernel Tests as root. You may be prompted for your sudo password."
trap sigint INT
sudo $${BUILD_WORKSPACE_DIRECTORY}/bazel-bin/Source/santa_driver/kernel_tests_bin
echo "Tests complete."
if kextstat | grep com.google.santa-driver; then
  sudo kextunload -b com.google.santa-driver >/dev/null
fi
""",
)
