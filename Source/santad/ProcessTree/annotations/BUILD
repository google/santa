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
    hdrs = ["originator.h"],
    srcs = ["originator.cc"],
    deps = [
        ":annotator",
        "//Source/santad/ProcessTree:process_tree",
    ],
)

santa_unit_test(
    name = "originator_test",
    srcs = ["originator_test.mm"],
    deps = [
        ":originator",
        "//Source/santad/ProcessTree:process",
        "//Source/santad/ProcessTree:process_tree_test_helpers",
        "//Source/santad/ProcessTree:process_tree_cc_proto",
    ],
)
