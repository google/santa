"""This module defines some helper rules."""

load("@build_bazel_rules_apple//apple:macos.bzl", "macos_unit_test")
load("@build_bazel_rules_apple//apple:resources.bzl", "apple_resource_group")

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
        minimum_os_version = "10.15",
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

def santa_unit_gtest(
        name,
        srcs = [],
        deps = [],
        sdk_dylibs = [],
        **kwargs):
    """Create a unit test that integrates with `googletest`"""

    # Note: In Bazel v5.0.0, there is a bug where `alwayslink` for
    # the `objc_library` rule is not respected when depended upon by the
    # `cc_test` rule: https://github.com/bazelbuild/bazel/issues/13510
    #
    # The workaround is to `-force_load` the library created from the
    # `objc_library` rule, which requires looking up the location of the
    # generated static library.
    native.objc_library(
        name = "%s_lib" % name,
        testonly = 1,
        srcs = srcs,
        alwayslink = 1,
        deps = deps,
        sdk_dylibs = sdk_dylibs,
        **kwargs
    )

    native.cc_test(
        name = "%s" % name,
        linkopts = [
          "-force_load $(location :%s_lib)" % name,
        ],
        deps = [
            ":%s_lib" % name,
            "//Source/common:TestRunnerGTest",
        ],
    )
