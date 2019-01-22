load("@build_bazel_rules_apple//apple:macos.bzl", "macos_unit_test")

objc_library(
    name = "logic_tests_lib",
    testonly = 1,
    srcs = glob([
        "Source/**/*.h",
        "Source/**/*.m",
        "Tests/LogicTests/*.m",
    ]),
    includes = [
        "Source/common",
        "Source/santabs",
        "Source/santactl",
        "Source/santactl/Commands",
        "Source/santactl/Commands/sync",
        "Source/santad",
        "Source/santad/DataLayer",
        "Source/santad/Logs",
    ],
    resources = glob(
        ["Tests/LogicTests/Resources/**"],
        exclude = [
            "**/BundleExample.app/**",
            "**/DirectoryBundle/**",
        ],
    ),
    sdk_dylibs = ["libz"],
    sdk_frameworks = [
        "AppKit",
        "DiskArbitration",
        "IOKit",
        "SecurityInterface",
    ],
    structured_resources = glob([
        "Tests/LogicTests/Resources/BundleExample.app/**",
        "Tests/LogicTests/Resources/DirectoryBundle/**",
    ]),
    deps = [
        "@FMDB//:fmdb",
        "@MOLCodesignChecker",
        "@MOLFCMClient",
        "@MOLXPCConnection",
        "@OCMock",
    ],
)

macos_unit_test(
    name = "logic_tests",
    bundle_id = "com.google.santa.LogicTests",
    minimum_os_version = "10.9",
    deps = [":logic_tests_lib"],
)
