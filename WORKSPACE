workspace(name = "santa")

load("@bazel_tools//tools/build_defs/repo:git.bzl",
     "git_repository",
     "new_git_repository",
)

git_repository(
    name = "build_bazel_rules_apple",
    remote = "https://github.com/bazelbuild/rules_apple.git",
    tag = "0.21.2",
)

load("@build_bazel_rules_apple//apple:repositories.bzl", "apple_rules_dependencies")
apple_rules_dependencies()

load("@build_bazel_apple_support//lib:repositories.bzl", "apple_support_dependencies")
apple_support_dependencies()

# Macops MOL* dependencies

git_repository(
    name = "MOLAuthenticatingURLSession",
    remote = "https://github.com/google/macops-molauthenticatingurlsession.git",
    commit = "7ef7af5c732eb8b9375af29a65262be5d97ad391", # tag = v3.0
    shallow_since = "1620062009 -0400",
)

git_repository(
    name = "MOLCertificate",
    remote = "https://github.com/google/macops-molcertificate.git",
    tag = "v2.1",
)

git_repository(
    name = "MOLCodesignChecker",
    remote = "https://github.com/google/macops-molcodesignchecker.git",
    tag = "v2.2",
)

git_repository(
    name = "MOLXPCConnection",
    remote = "https://github.com/google/macops-molxpcconnection.git",
    commit = "2c67c925c2b57fea9af551295d2b6711b38bb224", # tag = v2.1
    shallow_since = "1564684202 -0400",
)

# FMDB

new_git_repository(
    name = "FMDB",
    remote = "https://github.com/ccgus/fmdb.git",
    commit = "61e51fde7f7aab6554f30ab061cc588b28a97d04", # tag = 2.7.7
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

# OCMock

new_git_repository(
    name = "OCMock",
    remote = "https://github.com/erikdoe/ocmock",
    commit = "4a49ebb985bc16fae9489771aa35482ccbea14a3", # tag = v3.8.1
    shallow_since = "1609349457 +0100",
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
)
