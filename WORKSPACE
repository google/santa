workspace(name = "santa")

load(
    "@bazel_tools//tools/build_defs/repo:git.bzl",
    "git_repository",
    "new_git_repository",
)
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "build_bazel_rules_apple",
    sha256 = "f003875c248544009c8e8ae03906bbdacb970bc3e5931b40cd76cadeded99632",  # 1.1.0
    urls = ["https://github.com/bazelbuild/rules_apple/releases/download/1.1.0/rules_apple.1.1.0.tar.gz"],
)

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
    shallow_since = "1640416382 -0800",
)

load("@hedron_compile_commands//:workspace_setup.bzl", "hedron_compile_commands_setup")

hedron_compile_commands_setup()

# Googletest - tag: release-1.12.1
http_archive(
    name = "com_google_googletest",
    sha256 = "ab78fa3f912d44d38b785ec011a25f26512aaedc5291f51f3807c592b506d33a",
    strip_prefix = "googletest-58d77fa8070e8cec2dc1ed015d66b454c8d78850",
    urls = ["https://github.com/google/googletest/archive/58d77fa8070e8cec2dc1ed015d66b454c8d78850.zip"],
)

# Abseil - Abseil LTS branch, June 2022, Patch 1
http_archive(
    name = "com_google_absl",
    sha256 = "b9f490fae1c0d89a19073a081c3c588452461e5586e4ae31bc50a8f36339135e",
    strip_prefix = "abseil-cpp-8c0b94e793a66495e0b1f34a5eb26bd7dc672db0",
    urls = ["https://github.com/abseil/abseil-cpp/archive/8c0b94e793a66495e0b1f34a5eb26bd7dc672db0.zip"],
)

http_archive(
    name = "com_google_protobuf",
    patch_args = ["-p1"],
    patches = ["//external_patches/com_google_protobuf:10120.patch"],
    sha256 = "73c95c7b0c13f597a6a1fec7121b07e90fd12b4ed7ff5a781253b3afe07fc077",
    strip_prefix = "protobuf-3.21.6",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.21.6.tar.gz"],
)

# Note: Protobuf deps must be loaded after defining the ABSL archive since
# protobuf repo would pull an in earlier version of ABSL.
load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

# Macops MOL* dependencies

git_repository(
    name = "MOLAuthenticatingURLSession",
    commit = "7ef7af5c732eb8b9375af29a65262be5d97ad391",  # tag = v3.0
    remote = "https://github.com/google/macops-molauthenticatingurlsession.git",
    shallow_since = "1620062009 -0400",
)

git_repository(
    name = "MOLCertificate",
    commit = "288553b8ac75d7dd68159ef5b57652a506b8217c",  # tag = "v2.1",
    remote = "https://github.com/google/macops-molcertificate.git",
    shallow_since = "1561303966 -0400",
)

git_repository(
    name = "MOLCodesignChecker",
    commit = "7ef66f1df15997defd7651b0ea5d6d9ec65a5b4f",  # tag = "v2.2",
    remote = "https://github.com/google/macops-molcodesignchecker.git",
    shallow_since = "1561303990 -0400",
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
    commit = "afd2c6924e8a36cb872bc475248b978f743c6050",  # tag = v3.9.1
    patch_args = ["-p1"],
    patches = ["//external_patches/OCMock:503.patch"],
    remote = "https://github.com/erikdoe/ocmock",
    shallow_since = "1609349457 +0100",
)

# Fuzzing

http_archive(
    name = "rules_fuzzing",
    sha256 = "23bb074064c6f488d12044934ab1b0631e8e6898d5cf2f6bde087adb01111573",
    strip_prefix = "rules_fuzzing-0.3.1",
    urls = ["https://github.com/bazelbuild/rules_fuzzing/archive/v0.3.1.zip"],
)

load("@rules_fuzzing//fuzzing:repositories.bzl", "rules_fuzzing_dependencies")

rules_fuzzing_dependencies()

load("@rules_fuzzing//fuzzing:init.bzl", "rules_fuzzing_init")

rules_fuzzing_init()
