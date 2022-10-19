load("//:helper.bzl", "run_command", "santa_unit_test")

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

run_command(
    name = "install_profile",
    cmd = "osascript $${BUILD_WORKSPACE_DIRECTORY}/Testing/integration/install_profile.scpt $${BUILD_WORKSPACE_DIRECTORY}/$$1",
)
