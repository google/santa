licenses(["notice"])

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
        "SantaDecisionManager.cc",
        "SantaDecisionManager.h",
        "SantaDriver.cc",
        "SantaDriver.h",
        "SantaDriverClient.cc",
        "SantaDriverClient.h",
        "main.cc",
    ],
    copts = [
        "-mkernel",
        "-fapple-kext",
        "-Wno-ossharedptr-misuse",
        "-I__BAZEL_XCODE_SDKROOT__/System/Library/Frameworks/Kernel.framework/Headers",
    ],
    defines = [
        "KERNEL",
        "APPLE",
        "NeXT",
        "SANTA_VERSION=" + SANTA_VERSION,
    ],
    deps = [
        "//Source/common:SantaCache",
        "//Source/common:SNTKernelCommon",
        "//Source/common:SNTLoggingKernel",
        "//Source/common:SNTPrefixTreeKernel",
    ],
    alwayslink = 1,
)

macos_kernel_extension(
    name = "santa_driver",
    bundle_id = "com.google.santa-driver",
    bundle_name = "santa-driver",
    infoplists = ["Info.plist"],
    minimum_os_version = "10.9",
    version = "//:version",
    visibility = ["//:santa_package_group"],
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
        ":santa_driver",
    ],
    cmd = """
env
function sigint() {
  echo "\nInterrupted, unloading driver."
  sudo kextunload -b com.google.santa-driver >/dev/null
  exit 1
}
unzip -o $${BUILD_WORKSPACE_DIRECTORY}/bazel-bin/Source/santa_driver/santa_driver.zip >/dev/null
echo "Launching Kernel Tests as root. You may be prompted for your sudo password."
trap sigint INT
sudo $${BUILD_WORKSPACE_DIRECTORY}/bazel-bin/Source/santa_driver/kernel_tests_bin
echo "Tests complete."
if kextstat | grep com.google.santa-driver; then
  sudo kextunload -b com.google.santa-driver >/dev/null
fi
""",
)
