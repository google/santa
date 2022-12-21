load("fuzzing.bzl", "objc_fuzz_test")

objc_fuzz_test(
    name = "MachOParse",
    srcs = ["common/MachOParse.mm"],
    deps = [
        "//Source/common:SNTFileInfo",
    ],
    linkopts = ["-lsqlite3"],
    corpus = glob(["common/MachOParse_corpus/*"]),
)
