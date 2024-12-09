load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

cc_library(
    name = "annotator",
    hdrs = ["annotator.h"],
    deps = [
        "//Source/santad/ProcessTree:process_tree_cc_proto",
    ],
)

cc_library(
    name = "originator",
    srcs = ["originator.cc"],
    hdrs = ["originator.h"],
    deps = [
        ":annotator",
        "//Source/santad/ProcessTree:process",
        "//Source/santad/ProcessTree:process_tree",
        "//Source/santad/ProcessTree:process_tree_cc_proto",
        "@com_google_absl//absl/container:flat_hash_map",
    ],
)

cc_library(
    name = "ancestry",
    srcs = ["ancestry.cc"],
    hdrs = ["ancestry.h"],
    deps = [
        ":annotator",
        "//Source/santad/ProcessTree:process",
        "//Source/santad/ProcessTree:process_tree",
        "//Source/santad/ProcessTree:process_tree_cc_proto",
        "@com_google_absl//absl/container:flat_hash_map",
    ],
)

santa_unit_test(
    name = "originator_test",
    srcs = ["originator_test.mm"],
    deps = [
        ":originator",
        "//Source/santad/ProcessTree:process",
        "//Source/santad/ProcessTree:process_tree_cc_proto",
        "//Source/santad/ProcessTree:process_tree_test_helpers",
    ],
)

santa_unit_test(
    name = "ancestry_test",
    srcs = ["ancestry_test.mm"],
    deps = [
        ":ancestry",
        "//Source/santad/ProcessTree:process",
        "//Source/santad/ProcessTree:process_tree_cc_proto",
        "//Source/santad/ProcessTree:process_tree_test_helpers",
    ],
)
