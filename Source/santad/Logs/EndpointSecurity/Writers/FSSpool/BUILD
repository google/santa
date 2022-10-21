load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

proto_library(
    name = "binaryproto_proto",
    srcs = ["binaryproto.proto"],
    deps = [
        "@com_google_protobuf//:any_proto",
    ],
)

cc_proto_library(
    name = "binaryproto_cc_proto",
    deps = [
        ":binaryproto_proto",
    ],
)

cc_library(
    name = "binaryproto_cc_proto_library_wrapper",
    hdrs = ["binaryproto_proto_include_wrapper.h"],
    deps = [
        ":binaryproto_cc_proto",
    ],
)

cc_library(
    name = "fsspool",
    srcs = [
        "fsspool.cc",
        "fsspool_nowindows.cc",
    ],
    hdrs = [
        "fsspool.h",
        "fsspool_platform_specific.h",
    ],
    deps = [
        "@com_google_absl//absl/cleanup",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
    ],
)

cc_library(
    name = "fsspool_log_batch_writer",
    srcs = ["fsspool_log_batch_writer.cc"],
    hdrs = ["fsspool_log_batch_writer.h"],
    deps = [
        ":binaryproto_cc_proto",
        ":fsspool",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/synchronization",
    ],
)

santa_unit_test(
    name = "fsspool_test",
    srcs = ["fsspool_test.mm"],
    deps = [
        ":fsspool",
        ":fsspool_log_batch_writer",
        "@OCMock",
    ],
)
