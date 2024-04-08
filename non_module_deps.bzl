load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

def _non_module_deps_impl(ctx):
  # FMDB is used to access SQLite from Objective-C(++) code.
  git_repository(
    name = "FMDB",
    remote = "https://github.com/ccgus/fmdb.git",
    commit = "61e51fde7f7aab6554f30ab061cc588b28a97d04",
    shallow_since = "1589301502 -0700",
    build_file_content = """
objc_library(
    name = "FMDB",
    srcs = glob(["src/fmdb/*.m"], exclude=["src/fmdb.m"]),
    hdrs = glob(["src/fmdb/*.h"]),
    includes = ["src"],
    sdk_dylibs = ["sqlite3"],
    visibility = ["//visibility:public"],
)
""",
  )

  # OCMock is used in several tests.
  git_repository(
    name = "OCMock",
    build_file_content = """
objc_library(
    name = "OCMock",
    testonly = 1,
    hdrs = glob(["Source/OCMock/*.h"]),
    copts = [
        "-Wno-vla",
    ],
    includes = [
        "Source",
        "Source/OCMock",
    ],
    non_arc_srcs = glob(["Source/OCMock/*.m"]),
    pch = "Source/OCMock/OCMock-Prefix.pch",
    visibility = ["//visibility:public"],
)
""",
    commit = "afd2c6924e8a36cb872bc475248b978f743c6050",  # tag = v3.9.1
    patch_args = ["-p1"],
    patches = ["//external_patches/OCMock:503.patch"],
    remote = "https://github.com/erikdoe/ocmock",
    shallow_since = "1635703064 +0100",
)

non_module_deps = module_extension(implementation = _non_module_deps_impl)
