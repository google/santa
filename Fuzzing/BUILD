load("fuzzing.bzl", "objc_fuzz_test")

objc_fuzz_test(
    name = "MachOParse",
    srcs = ["MachOParse.mm"],
    linkopts = ["-lsqlite3"],
    deps = [
        "//Source/common:SNTFileInfo",
    ],
)
