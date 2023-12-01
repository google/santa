"""This module defines some helper rules."""

load("@bazel_skylib//rules:run_binary.bzl", "run_binary")
load("@build_bazel_rules_apple//apple:macos.bzl", "macos_unit_test")
load("@build_bazel_rules_apple//apple:resources.bzl", "apple_resource_group")
load("@rules_cc//cc:defs.bzl", "cc_library")

def run_command(name, cmd, **kwargs):
    """A rule to run a command."""
    native.genrule(
        name = "%s__gen" % name,
        executable = True,
        outs = ["%s.sh" % name],
        cmd = "echo '#!/bin/bash' > $@ && echo '%s' >> $@" % cmd,
        **kwargs
    )
    native.sh_binary(
        name = name,
        srcs = ["%s.sh" % name],
    )

def santa_unit_test(
        name,
        srcs = [],
        deps = [],
        size = "medium",
        minimum_os_version = "11.0",
        resources = [],
        structured_resources = [],
        copts = [],
        data = [],
        **kwargs):
    apple_resource_group(
        name = "%s_resources" % name,
        resources = resources,
        structured_resources = structured_resources,
    )

    native.objc_library(
        name = "%s_lib" % name,
        testonly = 1,
        srcs = srcs,
        deps = deps,
        copts = copts,
        data = [":%s_resources" % name],
        **kwargs
    )

    macos_unit_test(
        name = "%s" % name,
        bundle_id = "com.google.santa.UnitTest.%s" % name,
        minimum_os_version = minimum_os_version,
        deps = [":%s_lib" % name],
        size = size,
        data = data,
        visibility = ["//:__subpackages__"],
    )

def rust_cxx_bridge(name, src, deps = []):
    """
    Generates a cc_library target for interop with Rust code.

    More details: https://cxx.rs/build/bazel.html

    Args:
        name: By convention, RUST_LIBRARY_bridge. The cc_library will be named
              the same.
        src: Rust (.rs) file with a #[cxx::bridge] section.
        deps: Passed through to the cc_library target.
    """
    out_h = "gen/%s.h" % src
    out_cc = "gen/%s.cc" % src

    run_binary(
        name = "%s/generated" % name,
        srcs = [src],
        outs = [out_h, out_cc],
        args = [
            "$(location %s)" % src,
            "-o",
            "$(location %s)" % out_h,
            "-o",
            "$(location %s)" % out_cc,
        ],
        tool = "@cxxbridge-cmd//:cxxbridge",
    )

    cc_library(
        name = name,
        srcs = [out_cc],
        hdrs = [out_h],
        deps = deps,
    )
