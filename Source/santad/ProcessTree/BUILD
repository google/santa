load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
    features = ["-layering_check"],
)

cc_library(
    name = "process",
    hdrs = ["process.h"],
    deps = [
        "//Source/santad/ProcessTree/annotations:annotator",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/synchronization",
    ],
)

objc_library(
    name = "process_tree",
    srcs = [
        "process_tree.cc",
        "process_tree_macos.mm",
    ],
    hdrs = [
        "process_tree.h",
        "process_tree_macos.h",
    ],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":process",
        "//Source/santad/ProcessTree:process_tree_cc_proto",
        "//Source/santad/ProcessTree/annotations:annotator",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
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
    name = "SNTEndpointSecurityAdapter",
    srcs = ["SNTEndpointSecurityAdapter.mm"],
    hdrs = ["SNTEndpointSecurityAdapter.h"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":process_tree",
        "//Source/santad:EndpointSecurityAPI",
        "//Source/santad:EndpointSecurityMessage",
        "@com_google_absl//absl/status:statusor",
    ],
)

objc_library(
    name = "process_tree_test_helpers",
    srcs = ["process_tree_test_helpers.mm"],
    hdrs = ["process_tree_test_helpers.h"],
    deps = [
        ":process",
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
        "@com_google_absl//absl/synchronization",
    ],
)
