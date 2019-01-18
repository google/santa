load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")
load("//:cmd.bzl", "run_command")

objc_library(
    name = "kernel_tests_lib",
    srcs = [
        "Source/common/SNTKernelCommon.h",
        "Tests/KernelTests/main.mm",
    ],
    includes = ["Source/common"],
    sdk_frameworks = [
        "Foundation",
        "IOKit",
    ],
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
        ":santa-driver",
    ],
    cmd = """
function sigint() {
  echo "\nInterrupted, unloading driver."
  sudo kextunload -b com.google.santa-driver >/dev/null
  exit 1
}
unzip -o $${BUILD_WORKSPACE_DIRECTORY}/bazel-bin/santa-driver.zip >/dev/null
echo "Launching Kernel Tests as root. You may be prompted for your sudo password."
trap sigint INT
sudo $${BUILD_WORKSPACE_DIRECTORY}/bazel-bin/kernel_tests_bin
echo "Tests complete, unloading driver."
sudo kextunload -b com.google.santa-driver >/dev/null
""",
)
