load("@crate_index//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("@rules_rust//rust:defs.bzl", "rust_static_library", "rust_test")
load("//:helper.bzl", "rust_cxx_bridge", "santa_unit_test")

rust_static_library(
    name = "parquet_logger",
    srcs = ["parquet_logger.rs"],
    aliases = aliases(),
    proc_macro_deps = all_crate_deps(
        proc_macro = True,
    ),
    deps = all_crate_deps(
        normal = True,
    ),
)

cc_binary(
    name = "write_test_file",
    srcs = [
        "gen/parquet_logger.rs.h",
        "write_test_file.cc",
    ],
    deps = [":parquet_logger"],
)

rust_test(
    name = "parquet_logger_test",
    crate = ":parquet_logger",
)

rust_cxx_bridge(
    name = "parquet_bridge",
    src = "parquet_logger.rs",
    deps = [":parquet_logger"],
)

cc_library(
    name = "ParquetLogger",
    srcs = ["ParquetLogger.cc"],
    hdrs = ["ParquetLogger.h"],
    deps = [":parquet_bridge"],
)

santa_unit_test(
    name = "ParquetLoggerTest",
    srcs = ["ParquetLoggerTest.mm"],
    deps = [":ParquetLogger"],
)
