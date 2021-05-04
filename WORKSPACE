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
    tag = "v3.0",
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
    tag = "v2.1",
)

# FMDB

new_git_repository(
    name = "FMDB",
    remote = "https://github.com/ccgus/fmdb.git",
    tag = "2.7.7",
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
    tag = "v3.8.1",
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
