load("@build_bazel_rules_apple//apple:macos.bzl", "macos_bundle")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

licenses(["notice"])

objc_library(
    name = "SNTDatabaseTable",
    srcs = ["DataLayer/SNTDatabaseTable.m"],
    hdrs = ["DataLayer/SNTDatabaseTable.h"],
    deps = [
        "//Source/common:SNTLogging",
        "@FMDB",
    ],
)

objc_library(
    name = "SNTRuleTable",
    srcs = ["DataLayer/SNTRuleTable.m"],
    hdrs = ["DataLayer/SNTRuleTable.h"],
    deps = [
        ":SNTDatabaseTable",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTRule",
        "@MOLCertificate",
        "@MOLCodesignChecker",
    ],
)

objc_library(
    name = "SNTEventTable",
    srcs = ["DataLayer/SNTEventTable.m"],
    hdrs = ["DataLayer/SNTEventTable.h"],
    deps = [
        ":SNTDatabaseTable",
        "//Source/common:SNTStoredEvent",
        "@MOLCertificate",
    ],
)

objc_library(
    name = "SNTDatabaseController",
    srcs = ["SNTDatabaseController.m"],
    hdrs = ["SNTDatabaseController.h"],
    deps = [
        ":SNTEventTable",
        ":SNTRuleTable",
        "//Source/common:SNTLogging",
        "@FMDB",
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
        "//Source/common:SNTLogging",
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
    hdrs = [
        "Logs/SNTEventLog.h",
    ],
    deps = [
        ":SNTDatabaseController",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommon",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
        "@FMDB",
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
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommon",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTStoredEvent",
        "//Source/common:santa_objc_proto",
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
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommon",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredEvent",
    ],
)

objc_library(
    name = "file_event_logs",
    srcs = [
        "Logs/SNTFileEventLog.h",
        "Logs/SNTFileEventLog.m",
        "Logs/SNTSyslogEventLog.h",
    ],
    deps = [
        ":event_logs_common",
        "//Source/common:SNTCommon",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStrengthify",
    ],
)

objc_library(
    name = "event_logs",
    hdrs = ["Logs/SNTEventLog.h"],
    deps = [
        ":file_event_logs",
        ":protobuf_event_logs",
        ":syslog_event_logs",
        "//Source/common:SNTCommon",
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
        "SNTDaemonControlController.h",
        "SNTDaemonControlController.m",
        "SNTDatabaseController.h",
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
        ":SNTApplicationCoreMetrics",
        ":SNTDatabaseController",
        ":SNTExecutionController",
        ":endpoint_security_manager",
        ":event_logs",
        "//Source/common:SNTBlockMessage",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommon",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeviceEvent",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTXPCBundleServiceInterface",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCMetricServiceInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "//Source/common:SNTXPCUnprivilegedControlInterface",
        "//Source/common:SantaCache",
        "@FMDB",
        "@MOLCertificate",
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
    hdrs = [
        "EventProviders/EndpointSecurityTestUtil.h",
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

objc_library(
    name = "SNTDecisionCache",
    srcs = ["SNTDecisionCache.mm"],
    hdrs = ["SNTDecisionCache.h"],
    deps = [
      ":SNTDatabaseController",
      "//Source/common:SNTCommonEnums",
      "//Source/common:SNTCachedDecision",
      "//Source/common:SNTRule",
    ],
)

objc_library(
    name = "SNTCompilerController",
    srcs = ["SNTCompilerController.mm"],
    hdrs = ["SNTCompilerController.h"],
    deps = [
        ":EndpointSecurityMessage",
        ":SNTRuleTable",
        ":EndpointSecurityLogger",
        ":SNTDecisionCache",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommon",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
    ],
)

objc_library(
    name = "SNTNotificationQueue",
    srcs = ["SNTNotificationQueue.m"],
    hdrs = ["SNTNotificationQueue.h"],
    deps = [
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTXPCNotifierInterface",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "SNTSyncdQueue",
    srcs = ["SNTSyncdQueue.m"],
    hdrs = ["SNTSyncdQueue.h"],
    deps = [
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTXPCSyncServiceInterface",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "SNTPolicyProcessor",
    srcs = [
        "DataLayer/SNTDatabaseTable.h",
        "DataLayer/SNTRuleTable.h",
        "SNTPolicyProcessor.h",
        "SNTPolicyProcessor.m",
    ],
    deps = [
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommon",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "SNTExecutionController",
    srcs = ["SNTExecutionController.mm"],
    hdrs = ["SNTExecutionController.h"],
    deps = [
        ":SNTDecisionCache",
        ":EndpointSecurityMessage",
        ":SNTNotificationQueue",
        ":SNTPolicyProcessor",
        ":SNTSyncdQueue",
        "//Source/common:SNTBlockMessage",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommon",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTRule",
        "@MOLCodesignChecker",
    ],
)

objc_library(
    name = "SNTEndpointSecurityClientBase",
    hdrs = ["EventProviders/SNTEndpointSecurityClientBase.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
    ],
)

objc_library(
    name = "SNTEndpointSecurityClient",
    srcs = ["EventProviders/SNTEndpointSecurityClient.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityClient.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnrichedTypes",
        ":SNTEndpointSecurityClientBase",
        "//Source/common:SNTCommon",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
    ],
)

objc_library(
    name = "SNTEndpointSecurityRecorder",
    srcs = ["EventProviders/SNTEndpointSecurityRecorder.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityRecorder.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityAPI",
        ":EndpointSecurityLogger",
        ":SNTCompilerController",
        ":SNTEndpointSecurityClient",
        ":SNTEventProvider",
        "//Source/common:SNTLogging",
        "//Source/common:SNTPrefixTree",
    ],
)

objc_library(
    name = "SNTEndpointSecurityTamperResistance",
    srcs = ["EventProviders/SNTEndpointSecurityTamperResistance.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityTamperResistance.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":SNTEndpointSecurityClient",
        ":EndpointSecurityLogger",
        ":SNTEventProvider",
    ],
)

objc_library(
    name = "SNTEndpointSecurityAuthorizer",
    srcs = ["EventProviders/SNTEndpointSecurityAuthorizer.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityAuthorizer.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":SNTEndpointSecurityClient",
        ":SNTExecutionController",
        ":SNTCompilerController",
        ":SNTEventProvider",
    ],
)

objc_library(
    name = "SNTEndpointSecurityDeviceManager",
    srcs = ["EventProviders/SNTEndpointSecurityDeviceManager.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityDeviceManager.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityAPI",
        ":EndpointSecurityLogger",
        ":SNTEndpointSecurityClient",
        ":SNTEventProvider",
        "//Source/common:SNTLogging",
        "//Source/common:SNTDeviceEvent",
    ],
)

objc_library(
    name = "AuthResultCache",
    srcs = ["EventProviders/AuthResultCache.mm"],
    hdrs = ["EventProviders/AuthResultCache.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityClient",
        "//Source/common:SantaCache",
        "//Source/common:SNTLogging",
    ],
)

objc_library(
    name = "EndpointSecurityEnricher",
    srcs = ["EventProviders/EndpointSecurity/Enricher.mm"],
    hdrs = ["EventProviders/EndpointSecurity/Enricher.h"],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        "//Source/common:SNTLogging",
        "@thread-safe-lru//:thread-safe-lru",
    ],
)

objc_library(
    name = "EndpointSecurityEnrichedTypes",
    hdrs = ["EventProviders/EndpointSecurity/EnrichedTypes.h"],
    deps = [
        ":EndpointSecurityMessage",
    ],
)

objc_library(
    name = "EndpointSecuritySerializer",
    hdrs = ["Logs/EndpointSecurity/Serializers/Serializer.h"],
    deps = [
        ":EndpointSecurityMessage",
        ":EndpointSecurityEnrichedTypes",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerEmpty",
    srcs = ["Logs/EndpointSecurity/Serializers/Empty.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/Empty.h"],
    deps = [
        ":EndpointSecuritySerializer",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerBasicString",
    srcs = ["Logs/EndpointSecurity/Serializers/BasicString.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/BasicString.h"],
    deps = [
        ":EndpointSecuritySerializer",
        ":SNTDecisionCache",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredEvent",
    ],
)

objc_library(
    name = "EndpointSecurityWriter",
    hdrs = ["Logs/EndpointSecurity/Writers/Writer.h"],
)

objc_library(
    name = "EndpointSecurityWriterSyslog",
    srcs = ["Logs/EndpointSecurity/Writers/Syslog.mm"],
    hdrs = ["Logs/EndpointSecurity/Writers/Syslog.h"],
    deps = [
        ":EndpointSecurityWriter",
    ],
)

objc_library(
    name = "EndpointSecurityWriterFile",
    srcs = ["Logs/EndpointSecurity/Writers/File.mm"],
    hdrs = ["Logs/EndpointSecurity/Writers/File.h"],
    deps = [
        ":EndpointSecurityWriter",
    ]
)

objc_library(
    name = "EndpointSecurityWriterNull",
    srcs = ["Logs/EndpointSecurity/Writers/Null.mm"],
    hdrs = ["Logs/EndpointSecurity/Writers/Null.h"],
    deps = [
        ":EndpointSecurityWriter",
    ]
)

objc_library(
    name = "EndpointSecurityLogger",
    srcs = ["Logs/EndpointSecurity/Logger.mm"],
    hdrs = ["Logs/EndpointSecurity/Logger.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerBasicString",
        ":EndpointSecuritySerializerEmpty",
        ":EndpointSecurityWriter",
        ":EndpointSecurityWriterFile",
        ":EndpointSecurityWriterNull",
        ":EndpointSecurityWriterSyslog",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredEvent",
    ],
)

objc_library(
    name = "EndpointSecurityMessage",
    srcs = [
        "EventProviders/EndpointSecurity/EndpointSecurityAPI.h",
        "EventProviders/EndpointSecurity/Message.mm",
    ],
    hdrs = ["EventProviders/EndpointSecurity/Message.h"],
    deps = [
        ":EndpointSecurityClient",
    ],
)

objc_library(
    name = "EndpointSecurityClient",
    hdrs = ["EventProviders/EndpointSecurity/Client.h"],
)

objc_library(
    name = "EndpointSecurityAPI",
    srcs = ["EventProviders/EndpointSecurity/EndpointSecurityAPI.mm"],
    hdrs = ["EventProviders/EndpointSecurity/EndpointSecurityAPI.h"],
    deps = [
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
    ],
)

objc_library(
    name = "SNTDaemonControlController",
    srcs = [
        "EventProviders/SNTEventProvider.h",
        "SNTDaemonControlController.mm",
    ],
    hdrs = ["SNTDaemonControlController.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityLogger",
        ":SNTDatabaseController",
        ":SNTNotificationQueue",
        ":SNTPolicyProcessor",
        ":SNTSyncdQueue",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "@FMDB",
    ],
)

objc_library(
    name = "Metrics",
    srcs = ["metrics.mm"],
    hdrs = ["metrics.h"],
    deps = [
      ":SNTApplicationCoreMetrics",
      "//Source/common:SNTLogging",
      "//Source/common:SNTMetricSet",
      "//Source/common:SNTXPCMetricServiceInterface",
      "@MOLXPCConnection",
    ],
)

objc_library(
    name = "santad",
    srcs = ["santad.mm"],
    hdrs = ["santad.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":Metrics",
        ":SNTCompilerController",
        ":SNTDaemonControlController",
        ":SNTEndpointSecurityAuthorizer",
        ":SNTEndpointSecurityDeviceManager",
        ":SNTEndpointSecurityRecorder",
        ":SNTEndpointSecurityTamperResistance",
        ":SNTExecutionController",
        ":SNTNotificationQueue",
        ":SNTSyncdQueue",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTPrefixTree",
        "//Source/common:SNTXPCNotifierInterface",
    ],
)

objc_library(
    name = "santad_deps",
    srcs = ["santad_deps.mm"],
    hdrs = ["santad_deps.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityAPI",
        ":EndpointSecurityLogger",
        ":Metrics",
        ":SNTCompilerController",
        ":SNTDatabaseController",
        ":SNTExecutionController",
        ":SNTNotificationQueue",
        ":SNTSyncdQueue",
        "//Source/common:SNTPrefixTree",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCUnprivilegedControlInterface",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "santad_main",
    srcs = ["main.mm"],
    deps = [
        ":santad",
        ":santad_deps",
        ":SNTDaemonControlController",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCControlInterface",
    ],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    sdk_frameworks = [
        "DiskArbitration",
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
    entitlements = select({
        "//:adhoc_build": "com.google.santa.daemon.systemextension-adhoc.entitlements",
        # Non-adhoc builds get their entitlements from the provisioning profile.
        "//conditions:default": None,
    }),
    infoplists = ["Info.plist"],
    linkopts = ["-execute"],
    minimum_os_version = "10.15",
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "//profiles:daemon_dev",
    }),
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":santad_main"],
)

macos_bundle(
    name = "com.google.santa.daemon_orig",
    bundle_extension = "systemextension",
    bundle_id = "com.google.santa.daemon",
    codesignopts = [
        "--timestamp",
        "--force",
        "--options library,kill,runtime",
    ],
    entitlements = select({
        "//:adhoc_build": "com.google.santa.daemon.systemextension-adhoc.entitlements",
        # Non-adhoc builds get their entitlements from the provisioning profile.
        "//conditions:default": None,
    }),
    infoplists = ["Info.plist"],
    linkopts = ["-execute"],
    minimum_os_version = "10.15",
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "//profiles:daemon_dev",
    }),
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":santad_lib"],
)

santa_unit_test(
    name = "SNTExecutionControllerTest",
    srcs = [
        "DataLayer/SNTDatabaseTable.h",
        "DataLayer/SNTEventTable.h",
        "DataLayer/SNTRuleTable.h",
        "EventProviders/SNTEventProvider.h",
        "SNTExecutionController.h",
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
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTPrefixTree",
        "//Source/common:SNTRule",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:SantaCache",
        "@FMDB",
        "@MOLCertificate",
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
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
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
        "//Source/common:SNTLogging",
        "//Source/common:SNTPrefixTree",
        "//Source/common:SantaCache",
    ],
)

santa_unit_test(
    name = "SNTDeviceManagerTest",
    srcs = [
        "EventProviders/DiskArbitrationTestUtil.h",
        "EventProviders/SNTDeviceManager.h",
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
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeviceEvent",
        "//Source/common:SNTPrefixTree",
        "//Source/common:SantaCache",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTApplicationTest",
    srcs = [
        "SNTApplication.h",
        "SNTApplicationTest.m",
        "SNTDatabaseController.h",
    ],
    data = [
        "//Source/santad/testdata:binaryrules_testdata",
    ],
    minimum_os_version = "10.15",
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
    tags = ["exclusive"],
    deps = [
        ":EndpointSecurityTestLib",
        ":santad_lib",
        "//Source/common:SNTConfigurator",
        "@FMDB",
        "@MOLCertificate",
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
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTSystemInfo",
        "//Source/santametricservice/Formats:SNTMetricFormatTestHelper",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTProtobufEventLogTest",
    srcs = [
        "Logs/SNTLogOutput.h",
        "Logs/SNTProtobufEventLog.h",
        "Logs/SNTProtobufEventLogTest.m",
        "Logs/SNTSimpleMaildir.h",
    ],
    minimum_os_version = "10.15",
    deps = [
        ":EndpointSecurityTestLib",
        ":event_logs",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
        "//Source/common:santa_objc_proto",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerBasicStringTest",
    srcs = ["Logs/EndpointSecurity/Serializers/BasicStringTest.mm"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityMessage",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerBasicString",
        ":SNTDecisionCache",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTStoredEvent",
        "//Source/common:TestUtils",
        "@com_google_googletest//:gtest",
        "@OCMock",
    ],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
)

santa_unit_test(
    name = "AuthResultCacheTest",
    srcs = ["EventProviders/AuthResultCacheTest.mm"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityAPI",
        "//Source/common:TestUtils",
        "@com_google_googletest//:gtest",
        "@OCMock",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerEmptyTest",
    srcs = ["Logs/EndpointSecurity/Serializers/EmptyTest.mm"],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecuritySerializerEmpty",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecurityWriterFileTest",
    srcs = ["Logs/EndpointSecurity/Writers/FileTest.mm"],
    deps = [
        ":EndpointSecurityWriterFile",
        "//Source/common:TestUtils",
        "@com_google_googletest//:gtest",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecurityLoggerTest",
    srcs = ["Logs/EndpointSecurity/LoggerTest.mm"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerBasicString",
        ":EndpointSecuritySerializerEmpty",
        ":EndpointSecurityWriter",
        ":EndpointSecurityWriterFile",
        ":EndpointSecurityWriterNull",
        ":EndpointSecurityWriterSyslog",
        "//Source/common:SNTCommonEnums",
        "//Source/common:TestUtils",
        "@com_google_googletest//:gtest",
        "@OCMock",
    ],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
)

santa_unit_test(
    name = "EndpointSecurityClientTest",
    srcs = ["EventProviders/EndpointSecurity/ClientTest.mm"],
    deps = [
        ":EndpointSecurityClient",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecurityEnricherTest",
    srcs = ["EventProviders/EndpointSecurity/EnricherTest.mm"],
    deps = [
        ":EndpointSecurityEnricher",
        "//Source/common:TestUtils",
        "@OCMock",
    ],
    sdk_dylibs = [
        "bsm",
    ],
)

santa_unit_test(
    name = "EndpointSecurityMessageTest",
    srcs = ["EventProviders/EndpointSecurity/MessageTest.mm"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityMessage",
        "//Source/common:TestUtils",
        "@com_google_googletest//:gtest",
        "@OCMock",
    ],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
)


test_suite(
    name = "unit_tests",
    tests = [
        ":AuthResultCacheTest",
        ":EndpointSecurityClientTest",
        ":EndpointSecurityEnricherTest",
        ":EndpointSecurityLoggerTest",
        ":EndpointSecurityMessageTest",
        ":EndpointSecuritySerializerBasicStringTest",
        ":EndpointSecuritySerializerEmptyTest",
        ":EndpointSecurityWriterFileTest",
    ],
    visibility = ["//:santa_package_group"],
)

test_suite(
    name = "unit_tests_ORIG",
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
