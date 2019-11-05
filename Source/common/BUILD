package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2.0

load("//:helper.bzl", "santa_unit_test")

objc_library(
    name = "SNTBlockMessage",
    srcs = ["SNTBlockMessage.m"],
    hdrs = ["SNTBlockMessage.h"],
    deps = [
        ":SNTConfigurator",
        ":SNTStoredEvent",
    ],
)

objc_library(
    name = "SNTBlockMessage_SantaGUI",
    srcs = ["SNTBlockMessage.m"],
    hdrs = ["SNTBlockMessage.h"],
    defines = ["SANTAGUI"],
    deps = [
        ":SNTConfigurator",
        ":SNTStoredEvent",
    ],
)

objc_library(
    name = "SNTCachedDecision",
    srcs = ["SNTCachedDecision.m"],
    hdrs = ["SNTCachedDecision.h"],
    deps = [
        ":SNTCommonEnums",
        ":SNTKernelCommon",
    ],
)

cc_library(
    name = "SNTCommonEnums",
    hdrs = ["SNTCommonEnums.h"],
)

objc_library(
    name = "SNTConfigurator",
    srcs = ["SNTConfigurator.m"],
    hdrs = ["SNTConfigurator.h"],
    deps = [
        ":SNTCommonEnums",
        ":SNTLogging",
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
    name = "SNTKernelCommon",
    hdrs = ["SNTKernelCommon.h"],
)

cc_library(
    name = "SNTLoggingKernel",
    hdrs = ["SNTLogging.h"],
)

objc_library(
    name = "SNTLogging",
    srcs = ["SNTLogging.m"],
    hdrs = ["SNTLogging.h"],
)

cc_library(
    name = "SNTPrefixTree",
    srcs = ["SNTPrefixTree.cc"],
    hdrs = ["SNTPrefixTree.h"],
    copts = ["-std=c++11"],
    deps = [":SNTLogging"],
)

cc_library(
    name = "SNTPrefixTreeKernel",
    srcs = ["SNTPrefixTree.cc"],
    hdrs = ["SNTPrefixTree.h"],
    copts = [
        "-std=c++11",
        "-mkernel",
        "-I__BAZEL_XCODE_SDKROOT__/System/Library/Frameworks/Kernel.framework/Headers",
    ],
    defines = ["KERNEL"],
    deps = [":SNTLoggingKernel"],
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
    name = "SNTXPCControlInterface",
    srcs = ["SNTXPCControlInterface.m"],
    hdrs = ["SNTXPCControlInterface.h"],
    deps = [
        ":SNTStoredEvent",
        ":SNTXPCUnprivilegedControlInterface",
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
    name = "SNTXPCSyncdInterface",
    srcs = ["SNTXPCSyncdInterface.m"],
    hdrs = ["SNTXPCSyncdInterface.h"],
    deps = [
        ":SNTCommonEnums",
        ":SNTStoredEvent",
    ],
)

objc_library(
    name = "SNTXPCUnprivilegedControlInterface",
    srcs = ["SNTXPCUnprivilegedControlInterface.m"],
    hdrs = ["SNTXPCUnprivilegedControlInterface.h"],
    deps = [
        ":SNTCommonEnums",
        ":SNTKernelCommon",
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
    deps = ["SNTPrefixTree"],
)
