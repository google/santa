workspace(name = "santa")

load(
    "@bazel_tools//tools/build_defs/repo:git.bzl",
    "git_repository",
    "new_git_repository",
)
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Abseil LTS branch, Aug 2023
http_archive(
    name = "com_google_absl",
    strip_prefix = "abseil-cpp-20230802.0",
    urls = ["https://github.com/abseil/abseil-cpp/archive/refs/tags/20230802.0.tar.gz"],
)

http_archive(
    name = "com_google_protobuf",
    patch_args = ["-p1"],
    patches = ["//external_patches/com_google_protobuf:13636.patch"],
    sha256 = "07d69502e58248927b58c7d7e7424135272ba5b2852a753ab6b67e62d2d29355",
    strip_prefix = "protobuf-24.3",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v24.3.tar.gz"],
)

# We don't directly use rules_python but several dependencies do and they disagree
# about which version to use, so we force the latest.
http_archive(
    name = "rules_python",
    sha256 = "48a838a6e1983e4884b26812b2c748a35ad284fd339eb8e2a6f3adf95307fbcd",
    strip_prefix = "rules_python-0.16.2",
    url = "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.16.2.tar.gz",
)

http_archive(
    name = "build_bazel_rules_apple",
    sha256 = "8ac4c7997d863f3c4347ba996e831b5ec8f7af885ee8d4fe36f1c3c8f0092b2c",
    url = "https://github.com/bazelbuild/rules_apple/releases/download/2.5.0/rules_apple.2.5.0.tar.gz",
)

load("@build_bazel_rules_apple//apple:repositories.bzl", "apple_rules_dependencies")

apple_rules_dependencies()

load("@build_bazel_rules_swift//swift:repositories.bzl", "swift_rules_dependencies")

swift_rules_dependencies()

load(
    "@build_bazel_rules_swift//swift:extras.bzl",
    "swift_rules_extra_dependencies",
)

swift_rules_extra_dependencies()

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

# Note: Protobuf deps must be loaded after defining the ABSL archive since
# protobuf repo would pull an in earlier version of ABSL.
load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

# Macops MOL* dependencies

git_repository(
    name = "MOLAuthenticatingURLSession",
    commit = "38b5ee46edb262481b16f950266a11d8cb77127c",  # tag = v3.1
    remote = "https://github.com/google/macops-molauthenticatingurlsession.git",
    shallow_since = "1671479898 -0500",
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

# Moroz (for testing)

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "ae013bf35bd23234d1dea46b079f1e05ba74ac0321423830119d3e787ec73483",
    url = "https://github.com/bazelbuild/rules_go/releases/download/v0.36.0/rules_go-v0.36.0.zip",
)

http_archive(
    name = "bazel_gazelle",
    sha256 = "448e37e0dbf61d6fa8f00aaa12d191745e14f07c31cabfa731f0c8e8a4f41b97",
    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.28.0/bazel-gazelle-v0.28.0.tar.gz",
)

git_repository(
    name = "com_github_groob_moroz",
    commit = "cf740df50fa91bd5b5f2a8946571fad745eafece",
    patch_args = ["-p1"],
    patches = ["//external_patches/moroz:moroz.patch"],
    remote = "https://github.com/groob/moroz",
    shallow_since = "1594986926 -0400",
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")
load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
load("//external_patches/moroz:deps.bzl", "moroz_dependencies")

# gazelle:repository_macro external_patches/moroz/deps.bzl%moroz_dependencies
moroz_dependencies()

go_rules_dependencies()

go_register_toolchains(version = "1.19.3")

gazelle_dependencies()

# Fuzzing

# rules_fuzzing requires an older python for now
http_archive(
    name = "rules_python_fuzz",
    sha256 = "c03246c11efd49266e8e41e12931090b613e12a59e6f55ba2efd29a7cb8b4258",
    strip_prefix = "rules_python-0.11.0",
    url = "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.11.0.tar.gz",
)

git_repository(
    name = "rules_fuzzing",
    commit = "b193df79b10dbfb4c623bda23e825e835f12bada",  # Commit post PR 213 which fixes macOS
    remote = "https://github.com/bazelbuild/rules_fuzzing",
    repo_mapping = {"@rules_python": "@rules_python_fuzz"},
    shallow_since = "1668184479 -0500",
)

load("@rules_fuzzing//fuzzing:repositories.bzl", "rules_fuzzing_dependencies")

rules_fuzzing_dependencies()

load("@rules_fuzzing//fuzzing:init.bzl", "rules_fuzzing_init")

rules_fuzzing_init()
