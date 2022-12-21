load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")

def objc_fuzz_test(name, srcs, **kwargs):
  native.objc_library(
      name = "%s_lib" % name,
      srcs = srcs,
      **kwargs,
  )

  native.genrule(
    name = "%s_empty" % name,
    cmd = "touch $@",
    outs = ["%s.cc" % name],
  )

  cc_fuzz_test(
    name = name,
    srcs = [":%s_empty" % name],
    deps = ["%s_lib" % name],
    linkopts = kwargs.get('linkopts', []),
  )
