load("@cxxbridge_cmd_deps//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_binary")

licenses(["notice"])

# cxxbridge is a codegen tool for cxx.
#
# Note that you must build this target as @cxxbridge-cmd//:cxxbridge, not as
# //external_patches/cxxbridge-cmd:cxxbridge or any other path.
rust_binary(
    name = "cxxbridge",
    srcs = glob(["src/**/*.rs"]),
    aliases = aliases(),
    data = [
        "src/gen/include/cxx.h",
    ],
    edition = "2021",
    visibility = ["//visibility:public"],
    deps = all_crate_deps(),
)
