objc_library(
    name = "MachOParse_lib",
    srcs = ["MachOParse.mm"],
    deps = [
      "//Source/common:SNTFileInfo",
    ],
)

load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")

cc_fuzz_test(
  name = "MachOParse",
  srcs = ["fuzz.cc"],
  deps = ["MachOParse_lib"],
  linkopts = ["-lsqlite3"],  # TODO(nickmg): understand why the transitive dep on FMDB isn't doing this for us
)
