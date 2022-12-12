load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")
load("@rules_fuzzing//fuzzing:cc_defs.bzl", "fuzzing_decoration")
#load("santa_fuzz.bzl", "objc_fuzz_test")

# objc_fuzz_test(
#     name = "MachOParse",
#     srcs = ["MachOParse.mm"],
#     deps = [
#       #"//Source/common:SNTFileInfo",
#     ]
# )


name = "MachOParse"
engine = "@rules_fuzzing//fuzzing:cc_engine"
raw_library_name = name + "_raw_lib_"
raw_binary_name = name + "_raw_"

objc_library(
    name = raw_library_name,
    srcs = ["MachOParse.mm"],
    deps = [engine],
)

macos_command_line_application(
    name = raw_binary_name,
    deps = [
      raw_library_name,
      engine,
    ],
    minimum_os_version = "10.15"
)

fuzzing_decoration(
    name = name,
    raw_binary = raw_binary_name,
    engine = engine,
    test_tags = [
        "fuzz-test",
    ],
)
