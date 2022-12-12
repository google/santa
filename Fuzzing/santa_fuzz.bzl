load("@build_bazel_rules_apple//apple:macos.bzl", "macos_command_line_application")
load("@rules_fuzzing//fuzzing:cc_defs.bzl", "fuzzing_decoration")

def objc_fuzz_test(
        name,
        corpus = None,
        dicts = None,
        engine = "@rules_fuzzing//fuzzing:cc_engine",
        size = None,
        tags = None,
        timeout = None,
        **binary_kwargs):
    """
    cc_fuzz_test, but using macos_command_line_application instead of cc_binary
    internally.
    """
    raw_library_name = name + "_raw_lib_"
    raw_binary_name = name + "_raw_"

    binary_kwargs.setdefault("deps", [])
    binary_kwargs["deps"] += [engine]

    binary_kwargs.setdefault("tags", []).append("manual")

    objc_library(
        name = raw_library_name,
        **binary_kwargs
    )

    macos_command_line_application(
        name = raw_binary_name,
        deps = [
          raw_library_name,
          engine,
        ]
    )

    fuzzing_decoration(
        name = name,
        raw_binary = raw_binary_name,
        engine = engine,
        corpus = corpus,
        dicts = dicts,
        test_size = size,
        test_tags = (tags or []) + [
            "fuzz-test",
        ],
        test_timeout = timeout,
    )
