load("@build_bazel_rules_apple//apple:macos.bzl", "macos_bundle")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
    features = ["layering_check"],
)

licenses(["notice"])

objc_library(
    name = "database_controller",
    srcs = [
        "DataLayer/SNTDatabaseTable.h",
        "DataLayer/SNTDatabaseTable.m",
        "DataLayer/SNTEventTable.h",
        "DataLayer/SNTEventTable.m",
        "DataLayer/SNTRuleTable.h",
        "DataLayer/SNTRuleTable.m",
        "SNTDatabaseController.h",
        "SNTDatabaseController.m",
    ],
    deps = [
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
        "@FMDB",
        "@MOLCodesignChecker",
    ],
)

objc_library(
    name = "SNTEventProvider",
    hdrs = ["EventProviders/SNTEventProvider.h"],
    deps = [
        "//Source/common:SNTCommon",
    ],
)

objc_library(
    name = "endpoint_security_manager",
    srcs = [
        "EventProviders/SNTEndpointSecurityManager.h",
        "EventProviders/SNTEndpointSecurityManager.mm",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
    deps = [
        ":SNTEventProvider",
        "//Source/common:SNTCommon",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTPrefixTree",
        "//Source/common:SantaCache",
    ],
)

objc_library(
    name = "event_logs_common",
    srcs = [
        "DataLayer/SNTDatabaseTable.h",
        "DataLayer/SNTRuleTable.h",
        "Logs/SNTEventLog.h",
        "Logs/SNTEventLog.m",
        "Logs/SNTFileEventLog.h",
        "Logs/SNTProtobufEventLog.h",
        "Logs/SNTSyslogEventLog.h",
        "SNTDatabaseController.h",
    ],
    deps = [
        ":database_controller",
        "//Source/common:SNTAllowlistInfo",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommon",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
    ],
)

objc_library(
    name = "protobuf_event_logs",
    srcs = [
        "Logs/SNTLogOutput.h",
        "Logs/SNTProtobufEventLog.h",
        "Logs/SNTProtobufEventLog.m",
        "Logs/SNTSimpleMaildir.h",
        "Logs/SNTSimpleMaildir.m",
    ],
    deps = [
        ":event_logs_common",
        "//Source/common:SNTMetricSet",
        "//Source/common:log_objc_proto",
    ],
)

objc_library(
    name = "syslog_event_logs",
    srcs = [
        "EventProviders/SNTEndpointSecurityManager.h",
        "EventProviders/SNTEventProvider.h",
        "Logs/SNTSyslogEventLog.h",
        "Logs/SNTSyslogEventLog.m",
    ],
    deps = [
        ":endpoint_security_manager",
        ":event_logs_common",
    ],
)

objc_library(
    name = "file_event_logs",
    srcs = [
        "Logs/SNTFileEventLog.h",
        "Logs/SNTFileEventLog.m",
    ],
    deps = [
        ":event_logs_common",
    ],
)

objc_library(
    name = "event_logs",
    deps = [
        ":file_event_logs",
        ":protobuf_event_logs",
        ":syslog_event_logs",
    ],
)

objc_library(
    name = "santad_lib",
    srcs = [
        "DataLayer/SNTDatabaseTable.h",
        "DataLayer/SNTEventTable.h",
        "DataLayer/SNTRuleTable.h",
        "EventProviders/SNTCachingEndpointSecurityManager.h",
        "EventProviders/SNTCachingEndpointSecurityManager.mm",
        "EventProviders/SNTDeviceManager.h",
        "EventProviders/SNTDeviceManager.mm",
        "EventProviders/SNTEndpointSecurityManager.h",
        "EventProviders/SNTEventProvider.h",
        "SNTApplication.h",
        "SNTApplication.m",
        "SNTCompilerController.h",
        "SNTCompilerController.m",
        "SNTDaemonControlController.h",
        "SNTDaemonControlController.m",
        "SNTDatabaseController.h",
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
        ":database_controller",
        ":endpoint_security_manager",
        ":event_logs",
        "//Source/common:SNTBlockMessage",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeviceEvent",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCMetricServiceInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:SNTXPCSyncdInterface",
        "//Source/santad:SNTApplicationCoreMetrics",
        "@FMDB",
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
    sdk_frameworks = [
        "DiskArbitration",
        "IOKit",
    ],
)

objc_library(
    name = "DiskArbitrationTestLib",
    testonly = 1,
    srcs = [
        "EventProviders/DiskArbitrationTestUtil.h",
        "EventProviders/DiskArbitrationTestUtil.mm",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
    sdk_frameworks = [
        "DiskArbitration",
        "IOKit",
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
        "//Source/common:SNTCommon",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
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
    minimum_os_version = "10.15",
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
    deps = [
        ":EndpointSecurityTestLib",
        "//Source/common:SNTCommon",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTPrefixTree",
        "//Source/common:SantaCache",
    ],
)

santa_unit_test(
    name = "SNTDeviceManagerTest",
    srcs = [
        "EventProviders/SNTDeviceManagerTest.mm",
    ],
    minimum_os_version = "10.15",
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
    deps = [
        ":DiskArbitrationTestLib",
        ":EndpointSecurityTestLib",
        ":santad_lib",
        "//Source/common:SNTCommon",
        "//Source/common:SNTPrefixTree",
        "//Source/common:SantaCache",
        "@OCMock",
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

santa_unit_test(
    name = "SNTProtobufEventLogTest",
    srcs = [
        "Logs/SNTProtobufEventLogTest.m",
    ],
    minimum_os_version = "10.15",
    deps = [
        ":EndpointSecurityTestLib",
        ":event_logs",
        "//Source/common:SNTConfigurator",
        "//Source/common:log_objc_proto",
        "@OCMock",
    ],
)

test_suite(
    name = "unit_tests",
    tests = [
        ":SNTApplicationCoreMetricsTest",
        ":SNTApplicationTest",
        ":SNTDeviceManagerTest",
        ":SNTEndpointSecurityManagerTest",
        ":SNTEventTableTest",
        ":SNTExecutionControllerTest",
        ":SNTProtobufEventLogTest",
        ":SNTRuleTableTest",
    ],
    visibility = ["//:santa_package_group"],
)
