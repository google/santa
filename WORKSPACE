workspace(name = "santa")

load(
    "@bazel_tools//tools/build_defs/repo:git.bzl",
    "git_repository",
)
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

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
