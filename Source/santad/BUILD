load("@build_bazel_rules_apple//apple:macos.bzl", "macos_bundle")
load("//:helper.bzl", "santa_unit_test")

licenses(["notice"])

objc_library(
    name = "santad_lib",
    srcs = [
        "DataLayer/SNTDatabaseTable.h",
        "DataLayer/SNTDatabaseTable.m",
        "DataLayer/SNTEventTable.h",
        "DataLayer/SNTEventTable.m",
        "DataLayer/SNTRuleTable.h",
        "DataLayer/SNTRuleTable.m",
        "EventProviders/SNTCachingEndpointSecurityManager.h",
        "EventProviders/SNTCachingEndpointSecurityManager.mm",
        "EventProviders/SNTDriverManager.h",
        "EventProviders/SNTDriverManager.m",
        "EventProviders/SNTEndpointSecurityManager.h",
        "EventProviders/SNTEndpointSecurityManager.mm",
        "EventProviders/SNTEventProvider.h",
        "Logs/SNTEventLog.h",
        "Logs/SNTEventLog.m",
        "Logs/SNTFileEventLog.h",
        "Logs/SNTFileEventLog.m",
        "Logs/SNTSyslogEventLog.h",
        "Logs/SNTSyslogEventLog.m",
        "SNTApplication.h",
        "SNTApplication.m",
        "SNTCompilerController.h",
        "SNTCompilerController.m",
        "SNTDaemonControlController.h",
        "SNTDaemonControlController.m",
        "SNTDatabaseController.h",
        "SNTDatabaseController.m",
        "SNTExecutionController.h",
        "SNTExecutionController.m",
        "SNTNotificationQueue.h",
        "SNTNotificationQueue.m",
        "SNTPolicyProcessor.h",
        "SNTPolicyProcessor.m",
        "SNTSyncdQueue.h",
        "SNTSyncdQueue.m",
        "main.m",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
    sdk_frameworks = [
        "DiskArbitration",
        "IOKit",
    ],
    deps = [
        "//Source/common:SNTBlockMessage",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTKernelCommon",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTPrefixTree",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCMetricServiceInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:SNTXPCSyncdInterface",
        "//Source/common:SantaCache",
        "//Source/santad:SNTApplicationCoreMetrics",
        "@FMDB",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "SNTApplicationCoreMetrics",
    srcs = ["SNTApplicationCoreMetrics.m"],
    hdrs = ["SNTApplicationCoreMetrics.h"],
    deps = [
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTSystemInfo",
    ],
)

objc_library(
    name = "EndpointSecurityTestLib",
    testonly = 1,
    srcs = [
        "EventProviders/EndpointSecurityTestUtil.h",
        "EventProviders/EndpointSecurityTestUtil.mm",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
)

macos_bundle(
    name = "com.google.santa.daemon",
    bundle_extension = "systemextension",
    bundle_id = "com.google.santa.daemon",
    codesignopts = [
        "--timestamp",
        "--force",
        "--options library,kill,runtime",
    ],
    infoplists = ["Info.plist"],
    linkopts = ["-execute"],
    minimum_os_version = "10.9",
    provisioning_profile = select({
        "//:ci_build": None,
        "//conditions:default": "Santa_Daemon_Dev.provisionprofile",
    }),
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":santad_lib"],
)

santa_unit_test(
    name = "SNTExecutionControllerTest",
    srcs = [
        "SNTExecutionControllerTest.m",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
    deps = [
        ":santad_lib",
        "//Source/common:SNTBlockMessage",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTKernelCommon",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTPrefixTree",
        "//Source/common:SNTRule",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:SNTXPCSyncdInterface",
        "//Source/common:SantaCache",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTEventTableTest",
    srcs = [
        "DataLayer/SNTDatabaseTable.h",
        "DataLayer/SNTDatabaseTable.m",
        "DataLayer/SNTEventTable.h",
        "DataLayer/SNTEventTable.m",
        "DataLayer/SNTEventTableTest.m",
    ],
    deps = [
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredEvent",
        "@FMDB",
        "@MOLCertificate",
        "@MOLCodesignChecker",
    ],
)

santa_unit_test(
    name = "SNTRuleTableTest",
    srcs = [
        "DataLayer/SNTDatabaseTable.h",
        "DataLayer/SNTDatabaseTable.m",
        "DataLayer/SNTRuleTable.h",
        "DataLayer/SNTRuleTable.m",
        "DataLayer/SNTRuleTableTest.m",
    ],
    deps = [
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "@FMDB",
        "@MOLCertificate",
        "@MOLCodesignChecker",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityManagerTest",
    srcs = [
        "EventProviders/SNTEndpointSecurityManager.h",
        "EventProviders/SNTEndpointSecurityManager.mm",
        "EventProviders/SNTEndpointSecurityManagerTest.mm",
        "EventProviders/SNTEventProvider.h",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
    deps = [
        ":EndpointSecurityTestLib",
        "//Source/common:SNTKernelCommon",
        "//Source/common:SNTPrefixTree",
        "//Source/common:SantaCache",
    ],
)

santa_unit_test(
    name = "SNTApplicationTest",
    srcs = [
        "SNTApplicationTest.m",
    ],
    data = [
        "//Source/santad/testdata:binaryrules_testdata",
    ],
    minimum_os_version = "10.15",
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
    deps = [
        ":EndpointSecurityTestLib",
        ":santad_lib",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTApplicationBenchmark",
    srcs = [
        "SNTApplicationBenchmark.m",
    ],
    data = [
        "//Source/santad/testdata:binaryrules_testdata",
    ],
    minimum_os_version = "10.15",
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
    deps = [
        ":EndpointSecurityTestLib",
        ":santad_lib",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTApplicationCoreMetricsTest",
    srcs = [
        "SNTApplicationCoreMetricsTest.m",
    ],
    minimum_os_version = "10.15",
    deps = [
        ":SNTApplicationCoreMetrics",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTSystemInfo",
        "//Source/santametricservice/Formats:SNTMetricFormatTestHelper",
        "@OCMock",
    ],
)
