load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

cc_library(
  name = "base",
  hdrs = ["base.h"],
  deps = [
    "//Source/santad/ProcessTree:process_tree_cc_proto",
  ],
)
