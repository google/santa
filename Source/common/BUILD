load("//:helper.bzl", "santa_unit_test")
load("@rules_proto_grpc//objc:defs.bzl", "objc_proto_library")

package(
    default_visibility = ["//:santa_package_group"],
)

licenses(["notice"])

proto_library(
    name = "santa_proto",
    srcs = ["santa.proto"],
    deps = [
        "@com_google_protobuf//:any_proto",
        "@com_google_protobuf//:timestamp_proto",
    ],
)

objc_proto_library(
    name = "santa_objc_proto",
    copts = ["-fno-objc-arc"],
    non_arc_srcs = ["Santa.pbobjc.m"],
    protos = [":santa_proto"],
)

cc_library(
    name = "SantaCache",
    hdrs = ["SantaCache.h"],
    deps = ["//Source/common:SNTCommon"],
)

santa_unit_test(
    name = "SantaCacheTest",
    srcs = [
        "SantaCache.h",
        "SantaCacheTest.mm",
    ],
    deps = ["//Source/common:SNTCommon"],
)

objc_library(
    name = "SNTBlockMessage",
    srcs = ["SNTBlockMessage.m"],
    hdrs = ["SNTBlockMessage.h"],
    deps = [
        ":SNTConfigurator",
        ":SNTLogging",
        ":SNTStoredEvent",
        ":SNTSystemInfo",
    ],
)

objc_library(
    name = "SNTBlockMessage_SantaGUI",
    srcs = ["SNTBlockMessage.m"],
    hdrs = ["SNTBlockMessage.h"],
    defines = ["SANTAGUI"],
    deps = [
        ":SNTConfigurator",
        ":SNTDeviceEvent",
        ":SNTLogging",
        ":SNTStoredEvent",
        ":SNTSystemInfo",
    ],
)

objc_library(
    name = "SNTCachedDecision",
    srcs = ["SNTCachedDecision.m"],
    hdrs = ["SNTCachedDecision.h"],
    deps = [
        ":SNTCommon",
        ":SNTCommonEnums",
    ],
)

objc_library(
    name = "SNTDeviceEvent",
    srcs = ["SNTDeviceEvent.m"],
    hdrs = ["SNTDeviceEvent.h"],
    deps = [
        ":SNTCommonEnums",
    ],
)

objc_library(
    name = "SNTAllowlistInfo",
    srcs = ["SNTAllowlistInfo.m"],
    hdrs = ["SNTAllowlistInfo.h"],
)

objc_library(
    name = "SNTCommonEnums",
    hdrs = ["SNTCommonEnums.h"],
)

objc_library(
    name = "SNTConfigurator",
    srcs = ["SNTConfigurator.m"],
    hdrs = ["SNTConfigurator.h"],
    deps = [
        ":SNTCommonEnums",
        ":SNTStrengthify",
        ":SNTSystemInfo",
    ],
)

objc_library(
    name = "SNTDropRootPrivs",
    srcs = ["SNTDropRootPrivs.m"],
    hdrs = ["SNTDropRootPrivs.h"],
)

objc_library(
    name = "SNTFileInfo",
    srcs = ["SNTFileInfo.m"],
    hdrs = ["SNTFileInfo.h"],
    deps = [
        "@FMDB",
        "@MOLCodesignChecker",
    ],
)

cc_library(
    name = "SNTCommon",
    hdrs = ["SNTCommon.h"],
    defines = [
        "TARGET_OS_OSX",
        "TARGET_OS_MAC",
    ],
)

objc_library(
    name = "SNTLogging",
    srcs = ["SNTLogging.m"],
    hdrs = ["SNTLogging.h"],
    deps = [":SNTConfigurator"],
)

cc_library(
    name = "SNTPrefixTree",
    srcs = ["SNTPrefixTree.cc"],
    hdrs = ["SNTPrefixTree.h"],
    copts = ["-std=c++11"],
    deps = [":SNTLogging"],
)

objc_library(
    name = "SNTRule",
    srcs = ["SNTRule.m"],
    hdrs = ["SNTRule.h"],
    deps = [":SNTCommonEnums"],
)

objc_library(
    name = "SNTStoredEvent",
    srcs = ["SNTStoredEvent.m"],
    hdrs = ["SNTStoredEvent.h"],
    deps = [
        ":SNTCommonEnums",
        "@MOLCertificate",
    ],
)

cc_library(
    name = "SNTStrengthify",
    hdrs = ["SNTStrengthify.h"],
)

objc_library(
    name = "SNTSystemInfo",
    srcs = ["SNTSystemInfo.m"],
    hdrs = ["SNTSystemInfo.h"],
    sdk_frameworks = ["IOKit"],
)

objc_library(
    name = "SNTXPCBundleServiceInterface",
    srcs = ["SNTXPCBundleServiceInterface.m"],
    hdrs = ["SNTXPCBundleServiceInterface.h"],
    deps = [
        ":SNTStoredEvent",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "SNTXPCMetricServiceInterface",
    srcs = ["SNTXPCMetricServiceInterface.m"],
    hdrs = ["SNTXPCMetricServiceInterface.h"],
    deps = [
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "SNTXPCControlInterface",
    srcs = ["SNTXPCControlInterface.m"],
    hdrs = ["SNTXPCControlInterface.h"],
    deps = [
        ":SNTCommonEnums",
        ":SNTConfigurator",
        ":SNTRule",
        ":SNTStoredEvent",
        ":SNTXPCUnprivilegedControlInterface",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "SNTXPCNotifierInterface",
    srcs = ["SNTXPCNotifierInterface.m"],
    hdrs = ["SNTXPCNotifierInterface.h"],
    deps = [
        ":SNTCommonEnums",
        ":SNTXPCBundleServiceInterface",
    ],
)

objc_library(
    name = "SNTMetricSet",
    srcs = ["SNTMetricSet.m"],
    hdrs = ["SNTMetricSet.h"],
    deps = [":SNTCommonEnums"],
)

objc_library(
    name = "SNTXPCSyncServiceInterface",
    srcs = ["SNTXPCSyncServiceInterface.m"],
    hdrs = ["SNTXPCSyncServiceInterface.h"],
    deps = [
        ":SNTCommonEnums",
        ":SNTStoredEvent",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "SNTXPCUnprivilegedControlInterface",
    srcs = ["SNTXPCUnprivilegedControlInterface.m"],
    hdrs = ["SNTXPCUnprivilegedControlInterface.h"],
    deps = [
        ":SNTCommon",
        ":SNTCommonEnums",
        ":SNTRule",
        ":SNTStoredEvent",
        ":SNTXPCBundleServiceInterface",
        "@MOLCertificate",
        "@MOLXPCConnection",
    ],
)

santa_unit_test(
    name = "SNTFileInfoTest",
    srcs = ["SNTFileInfoTest.m"],
    resources = [
        "testdata/32bitplist",
        "testdata/bad_pagezero",
        "testdata/missing_pagezero",
    ],
    structured_resources = glob([
        "testdata/BundleExample.app/**",
        "testdata/DirectoryBundle/**",
    ]),
    deps = [":SNTFileInfo"],
)

santa_unit_test(
    name = "SNTPrefixTreeTest",
    srcs = ["SNTPrefixTreeTest.mm"],
    deps = [":SNTPrefixTree"],
)

santa_unit_test(
    name = "SNTMetricSetTest",
    srcs = ["SNTMetricSetTest.m"],
    deps = [":SNTMetricSet"],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTFileInfoTest",
        ":SNTMetricSetTest",
        ":SNTPrefixTreeTest",
        ":SantaCacheTest",
    ],
    visibility = ["//:santa_package_group"],
)
