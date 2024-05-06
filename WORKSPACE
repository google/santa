workspace(name = "santa")

load(
    "@bazel_tools//tools/build_defs/repo:git.bzl",
    "git_repository",
    "new_git_repository",
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

# Rust support:

# To find additional information on this release or newer ones visit:
# https://github.com/bazelbuild/rules_rust/releases
http_archive(
    name = "rules_rust",
    sha256 = "36ab8f9facae745c9c9c1b33d225623d976e78f2cc3f729b7973d8c20934ab95",
    urls = ["https://github.com/bazelbuild/rules_rust/releases/download/0.31.0/rules_rust-v0.31.0.tar.gz"],
)

load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains")

rules_rust_dependencies()

rust_register_toolchains(
    edition = "2021",
)

load("@rules_rust//crate_universe:repositories.bzl", "crate_universe_dependencies")

crate_universe_dependencies()

load("@rules_rust//crate_universe:defs.bzl", "crates_repository")

# If we don't specify which platforms to build, rust_*_library targets will
# select() across platforms that are not guaranteed to exist in the local Bazel,
# which breaks the build.
#
# This is probably a Bazel bug, because rules_rust
# specifies the correct module dependency and Bazel just ignores it and fetches
# an old version.
#
# TODO(the80srobot): Find the right Bazel subproject and file a bug.
RUST_SUPPORTED_PLATFORM_TRIPLES = [
    "i686-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
]

crates_repository(
    name = "crate_index",
    cargo_lockfile = "//:Cargo.lock",
    manifests = [
        # Root Cargo file.
        "//:Cargo.toml",
        # The below this line must be kept in sync with the workspaces listed in
        # the root Cargo file.
        "//:Source/santad/Logs/EndpointSecurity/ParquetLogger/Cargo.toml",
    ],
    supported_platform_triples = RUST_SUPPORTED_PLATFORM_TRIPLES,
)

load("@crate_index//:defs.bzl", "crate_repositories")

crate_repositories()

# cxxbridge is a codegen tool for Rust/C++ bindings. To understand why this is
# set up the way it is, read
# http://bazelbuild.github.io/rules_rust/crate_universe.html#binary-dependencies.
http_archive(
    name = "cxxbridge-cmd",
    build_file = "//external_patches/cxxbridge-cmd:BUILD",
    sha256 = "dc5db43c367778010dff55b602f71eccff712b8edf54a3f08687bd1c7cbad6df",
    strip_prefix = "cxxbridge-cmd-1.0.110",
    type = "tar.gz",
    urls = ["https://crates.io/api/v1/crates/cxxbridge-cmd/1.0.110/download"],
)

# See above for notes.
crates_repository(
    name = "cxxbridge_cmd_deps",
    cargo_lockfile = "//external_patches/cxxbridge-cmd:Cargo.lock",
    lockfile = "//external_patches/cxxbridge-cmd:Cargo.Bazel.lock",
    manifests = ["@cxxbridge-cmd//:Cargo.toml"],
    supported_platform_triples = RUST_SUPPORTED_PLATFORM_TRIPLES,
)
load("@cxxbridge_cmd_deps//:defs.bzl", cxxbridge_cmd_deps = "crate_repositories")
cxxbridge_cmd_deps()
