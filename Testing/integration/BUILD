load("//:helper.bzl", "santa_unit_test")
load("//:helper.bzl", "run_command")
load(
    "@build_bazel_rules_apple//apple:macos.bzl",
    "macos_command_line_application",
)

package(default_visibility = ["//:santa_package_group"])

licenses(["notice"])

santa_unit_test(
    name = "SNTExecTest",
    srcs = [
        "SNTExecTest.m",
    ],
    data = [
        "//Source/santad/testdata:binaryrules_testdata",
    ],
    minimum_os_version = "10.15",
    deps = [],
)

test_suite(
    name = "integration_tests",
    tests = [
        ":SNTExecTest",
    ],
)

objc_library(
    name = "logging_benchmarks_lib",
    testonly = 1,
    srcs = [
        "SNTLoggingBenchmarks.m",
    ],
    deps = [
        "//Source/santad:EndpointSecurityTestLib",
        "//Source/santad:event_logs",
    ],
)

macos_command_line_application(
    name = "logging_benchmarks_bin",
    testonly = 1,
    bundle_id = "com.goole.santa.benchmark.logging",
    minimum_os_version = "10.15",
    deps = [":logging_benchmarks_lib"],
)

run_command(
    name = "install_profile",
    cmd = "osascript $${BUILD_WORKSPACE_DIRECTORY}/Testing/integration/install_profile.scpt $${BUILD_WORKSPACE_DIRECTORY}/$$1",
)

sh_test(
    name = "USBStatusCheck",
    srcs = [
        "test_usb_config_change.sh",
    ],
    deps = [
        "install_profile.scpt",
        "configs/usb-block.mobileconfig",
    ],
)

test_suite(
    name = "config_changes",
    tests = [
        ":USBStatusCheck",
    ],
)
