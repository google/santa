load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

cc_library(
    name = "process",
    hdrs = ["process.h"],
    deps = [
        "//Source/santad/ProcessTree/Annotations:base",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/synchronization",
    ],
)

objc_library(
    name = "process_tree",
    srcs = [
        "tree.cc",
        "tree_macos.mm",
    ],
    hdrs = ["tree.h"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":process",
        "//Source/santad/ProcessTree/Annotations:base",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/synchronization",
    ],
)

proto_library(
    name = "process_tree_proto",
    srcs = ["process_tree.proto"],
)

cc_proto_library(
    name = "process_tree_cc_proto",
    deps = [":process_tree_proto"],
)

objc_library(
    name = "tree_test_helpers",
    srcs = ["tree_test_helpers.mm"],
    hdrs = ["tree_test_helpers.h"],
    deps = [
        ":process_tree",
        "@com_google_absl//absl/synchronization",
    ],
)

santa_unit_test(
    name = "process_tree_test",
    srcs = ["tree_test.mm"],
    deps = [
        ":process",
        ":tree_test_helpers",
        "//Source/santad/ProcessTree/Annotations:base",
    ],
)
