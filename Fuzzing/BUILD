load("fuzzing.bzl", "objc_fuzz_test")

objc_fuzz_test(
    name = "MachOParse",
    srcs = ["common/MachOParse.mm"],
    corpus = glob(["common/MachOParse_corpus/*"]),
    linkopts = ["-lsqlite3"],
    deps = [
        "//Source/common:SNTFileInfo",
    ],
)
