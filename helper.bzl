"""This module defines some helper rules."""

load("@build_bazel_rules_apple//apple:macos.bzl", "macos_unit_test")

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

def santa_unit_test(name,
                    srcs = [],
                    deps = [],
                    size = "medium",
                    minimum_os_version = "10.9",
                    copts = [],
                    **kwargs):
  native.objc_library(
      name = "%s_lib" % name,
      testonly = 1,
      srcs = srcs,
      deps = deps,
      copts = copts,
      **kwargs
  )

  macos_unit_test(
      name = "%s" % name,
      bundle_id = "com.google.santa.UnitTest.%s" % name,
      minimum_os_version = minimum_os_version,
      deps = [":%s_lib" % name],
      size = size,
  )
