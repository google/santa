workspace(name = "santa")

load(
    "@bazel_tools//tools/build_defs/repo:git.bzl",
    "git_repository",
    "new_git_repository",
)
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "build_bazel_rules_apple",
    sha256 = "36072d4f3614d309d6a703da0dfe48684ec4c65a89611aeb9590b45af7a3e592", # 1.0.1
    urls = ["https://github.com/bazelbuild/rules_apple/releases/download/1.0.1/rules_apple.1.0.1.tar.gz"],
)


http_archive(
    name = "rules_proto_grpc",
    sha256 = "28724736b7ff49a48cb4b2b8cfa373f89edfcb9e8e492a8d5ab60aa3459314c8",
    strip_prefix = "rules_proto_grpc-4.0.1",
    urls = ["https://github.com/rules-proto-grpc/rules_proto_grpc/archive/4.0.1.tar.gz"],
)

load("@rules_proto_grpc//:repositories.bzl", "rules_proto_grpc_repos", "rules_proto_grpc_toolchains")

rules_proto_grpc_toolchains()

rules_proto_grpc_repos()

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")

rules_proto_dependencies()

rules_proto_toolchains()

load("@rules_proto_grpc//objc:repositories.bzl", rules_proto_grpc_objc_repos = "objc_repos")

rules_proto_grpc_objc_repos()

load("@build_bazel_rules_apple//apple:repositories.bzl", "apple_rules_dependencies")

apple_rules_dependencies()

load("@build_bazel_apple_support//lib:repositories.bzl", "apple_support_dependencies")

apple_support_dependencies()

# Hedron Bazel Compile Commands Extractor
# Allows integrating with clangd
# https://github.com/hedronvision/bazel-compile-commands-extractor
git_repository(
    name = "hedron_compile_commands",
    commit = "92db741ee6dee0c4a83a5c58be7747df7b89ed10",
    remote = "https://github.com/hedronvision/bazel-compile-commands-extractor.git",
    shallow_since = "1638167585 -0800",
)

load("@hedron_compile_commands//:workspace_setup.bzl", "hedron_compile_commands_setup")

hedron_compile_commands_setup()

# Macops MOL* dependencies

git_repository(
    name = "MOLAuthenticatingURLSession",
    commit = "7ef7af5c732eb8b9375af29a65262be5d97ad391",  # tag = v3.0
    remote = "https://github.com/google/macops-molauthenticatingurlsession.git",
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
    commit = "2c67c925c2b57fea9af551295d2b6711b38bb224",  # tag = v2.1
    remote = "https://github.com/google/macops-molxpcconnection.git",
    shallow_since = "1564684202 -0400",
)

# FMDB

new_git_repository(
    name = "FMDB",
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
    commit = "61e51fde7f7aab6554f30ab061cc588b28a97d04",  # tag = 2.7.7
    remote = "https://github.com/ccgus/fmdb.git",
    shallow_since = "1589301502 -0700",
)

# OCMock

new_git_repository(
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
    commit = "4a49ebb985bc16fae9489771aa35482ccbea14a3",  # tag = v3.8.1
    remote = "https://github.com/erikdoe/ocmock",
    shallow_since = "1609349457 +0100",
)
