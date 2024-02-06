load("//:helper.bzl", "santa_unit_test")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")

cc_library(
    name = "process",
    hdrs = ["process.h"],
    deps = [
        "//Source/santad/ProcessTree/annotations:annotator",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/synchronization",
    ],
    visibility = ["//:santa_package_group"],
)

objc_library(
    name = "process_tree",
    srcs = [
        "process_tree.cc",
        "process_tree_macos.mm",
    ],
    hdrs = ["process_tree.h"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":process",
        "//Source/santad/ProcessTree/annotations:annotator",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/synchronization",
    ],
    visibility = ["//:santa_package_group"],
)

proto_library(
    name = "process_tree_proto",
    srcs = ["process_tree.proto"],
    visibility = ["//:santa_package_group"],
)

cc_proto_library(
    name = "process_tree_cc_proto",
    deps = [":process_tree_proto"],
    visibility = ["//:santa_package_group"],
)

objc_library(
    name = "process_tree_test_helpers",
    srcs = ["process_tree_test_helpers.mm"],
    hdrs = ["process_tree_test_helpers.h"],
    deps = [
        ":process_tree",
        "@com_google_absl//absl/synchronization",
    ],
)

santa_unit_test(
    name = "process_tree_test",
    srcs = ["process_tree_test.mm"],
    deps = [
        ":process",
        ":process_tree_test_helpers",
        "//Source/santad/ProcessTree/annotations:annotator",
    ],
)
