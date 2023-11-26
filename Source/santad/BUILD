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
        "//Source/common:Platform",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "@MOLCertificate",
        "@MOLCodesignChecker",
    ],
)

objc_library(
    name = "WatchItemPolicy",
    hdrs = ["DataLayer/WatchItemPolicy.h"],
)

objc_library(
    name = "WatchItems",
    srcs = ["DataLayer/WatchItems.mm"],
    hdrs = ["DataLayer/WatchItems.h"],
    deps = [
        ":SNTEndpointSecurityEventHandler",
        ":WatchItemPolicy",
        "//Source/common:PrefixTree",
        "//Source/common:SNTLogging",
        "//Source/common:String",
        "//Source/common:Unit",
    ],
)

santa_unit_test(
    name = "WatchItemsTest",
    srcs = ["DataLayer/WatchItemsTest.mm"],
    deps = [
        ":WatchItemPolicy",
        ":WatchItems",
        "//Source/common:PrefixTree",
        "//Source/common:TestUtils",
        "//Source/common:Unit",
        "@OCMock",
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
    name = "SNTEndpointSecurityEventHandler",
    hdrs = ["EventProviders/SNTEndpointSecurityEventHandler.h"],
    deps = [
        ":EndpointSecurityMessage",
        ":Metrics",
        ":WatchItemPolicy",
    ],
)

objc_library(
    name = "SNTApplicationCoreMetrics",
    srcs = ["SNTApplicationCoreMetrics.mm"],
    hdrs = ["SNTApplicationCoreMetrics.h"],
    deps = [
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTSystemInfo",
        "//Source/common:SystemResources",
    ],
)

objc_library(
    name = "DiskArbitrationTestLib",
    testonly = 1,
    srcs = ["EventProviders/DiskArbitrationTestUtil.mm"],
    hdrs = ["EventProviders/DiskArbitrationTestUtil.h"],
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
        ":SNTRuleTable",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTRule",
        "//Source/common:SantaCache",
        "//Source/common:SantaVnode",
        "//Source/common:SantaVnodeHash",
    ],
)

objc_library(
    name = "SNTCompilerController",
    srcs = ["SNTCompilerController.mm"],
    hdrs = ["SNTCompilerController.h"],
    deps = [
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTRuleTable",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
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
        "SNTPolicyProcessor.m",
    ],
    hdrs = ["SNTPolicyProcessor.h"],
    deps = [
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeepCopy",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTRule",
        "@FMDB",
        "@MOLCertificate",
        "@MOLCodesignChecker",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "TTYWriter",
    srcs = ["TTYWriter.mm"],
    hdrs = ["TTYWriter.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        "//Source/common:SNTLogging",
        "//Source/common:String",
    ],
)

objc_library(
    name = "SNTExecutionController",
    srcs = ["SNTExecutionController.mm"],
    hdrs = ["SNTExecutionController.h"],
    deps = [
        ":EndpointSecurityMessage",
        ":SNTDecisionCache",
        ":SNTEventTable",
        ":SNTNotificationQueue",
        ":SNTPolicyProcessor",
        ":SNTRuleTable",
        ":SNTSyncdQueue",
        ":TTYWriter",
        "//Source/common:BranchPrediction",
        "//Source/common:PrefixTree",
        "//Source/common:SNTBlockMessage",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeepCopy",
        "//Source/common:SNTDropRootPrivs",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SantaVnode",
        "//Source/common:String",
        "//Source/common:Unit",
        "@MOLCodesignChecker",
        "@com_google_absl//absl/synchronization",
    ],
)

objc_library(
    name = "SNTEndpointSecurityClientBase",
    hdrs = ["EventProviders/SNTEndpointSecurityClientBase.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityClient",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":WatchItemPolicy",
    ],
)

objc_library(
    name = "SNTEndpointSecurityClient",
    srcs = ["EventProviders/SNTEndpointSecurityClient.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityClient.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityClient",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":SNTEndpointSecurityClientBase",
        ":WatchItemPolicy",
        "//Source/common:BranchPrediction",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SystemResources",
    ],
)

objc_library(
    name = "SNTEndpointSecurityRecorder",
    srcs = ["EventProviders/SNTEndpointSecurityRecorder.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityRecorder.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":SNTCompilerController",
        ":SNTEndpointSecurityClient",
        ":SNTEndpointSecurityEventHandler",
        "//Source/common:PrefixTree",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:String",
        "//Source/common:Unit",
    ],
)

objc_library(
    name = "SNTEndpointSecurityTamperResistance",
    srcs = ["EventProviders/SNTEndpointSecurityTamperResistance.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityTamperResistance.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":SNTEndpointSecurityClient",
        ":SNTEndpointSecurityEventHandler",
        ":WatchItemPolicy",
        "//Source/common:SNTLogging",
    ],
)

objc_library(
    name = "SNTEndpointSecurityAuthorizer",
    srcs = ["EventProviders/SNTEndpointSecurityAuthorizer.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityAuthorizer.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":SNTCompilerController",
        ":SNTEndpointSecurityClient",
        ":SNTEndpointSecurityEventHandler",
        ":SNTExecutionController",
        "//Source/common:BranchPrediction",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTLogging",
    ],
)

objc_library(
    name = "SNTEndpointSecurityFileAccessAuthorizer",
    srcs = ["EventProviders/SNTEndpointSecurityFileAccessAuthorizer.mm"],
    hdrs = ["EventProviders/SNTEndpointSecurityFileAccessAuthorizer.h"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":RateLimiter",
        ":SNTDecisionCache",
        ":SNTEndpointSecurityClient",
        ":SNTEndpointSecurityEventHandler",
        ":TTYWriter",
        ":WatchItemPolicy",
        ":WatchItems",
        "//Source/common:Platform",
        "//Source/common:SNTBlockMessage",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileAccessEvent",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTStrengthify",
        "//Source/common:SantaCache",
        "//Source/common:SantaVnode",
        "//Source/common:SantaVnodeHash",
        "//Source/common:String",
        "@MOLCertificate",
        "@MOLCodesignChecker",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
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
        ":EndpointSecurityMessage",
        ":Metrics",
        ":SNTEndpointSecurityClient",
        ":SNTEndpointSecurityEventHandler",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTDeviceEvent",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
    ],
)

objc_library(
    name = "AuthResultCache",
    srcs = ["EventProviders/AuthResultCache.mm"],
    hdrs = ["EventProviders/AuthResultCache.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityClient",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SantaCache",
        "//Source/common:SantaVnode",
        "//Source/common:SantaVnodeHash",
    ],
)

objc_library(
    name = "RateLimiter",
    srcs = ["EventProviders/RateLimiter.mm"],
    hdrs = ["EventProviders/RateLimiter.h"],
    deps = [
        ":Metrics",
        "//Source/common:BranchPrediction",
        "//Source/common:SystemResources",
    ],
)

objc_library(
    name = "EndpointSecurityEnricher",
    srcs = ["EventProviders/EndpointSecurity/Enricher.mm"],
    hdrs = ["EventProviders/EndpointSecurity/Enricher.h"],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        "//Source/common:SNTLogging",
        "//Source/common:SantaCache",
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
    srcs = ["Logs/EndpointSecurity/Serializers/Serializer.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/Serializer.h"],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
        ":SNTDecisionCache",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerUtilities",
    srcs = ["Logs/EndpointSecurity/Serializers/Utilities.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/Utilities.h"],
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
        ":SNTDecisionCache",
        "//Source/common:SantaCache",
        "//Source/common:SantaVnode",
        "//Source/common:SantaVnodeHash",
        "//Source/common:String",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerEmpty",
    srcs = ["Logs/EndpointSecurity/Serializers/Empty.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/Empty.h"],
    deps = [
        ":EndpointSecuritySerializer",
        "//Source/common:SNTCachedDecision",
    ],
)

objc_library(
    name = "EndpointSecuritySanitizableString",
    srcs = ["Logs/EndpointSecurity/Serializers/SanitizableString.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/SanitizableString.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityMessage",
        "//Source/common:String",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerBasicString",
    srcs = ["Logs/EndpointSecurity/Serializers/BasicString.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/BasicString.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecuritySanitizableString",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerUtilities",
        ":SNTDecisionCache",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredEvent",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerProtobuf",
    srcs = ["Logs/EndpointSecurity/Serializers/Protobuf.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/Protobuf.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerUtilities",
        ":SNTDecisionCache",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTStoredEvent",
        "//Source/common:String",
        "//Source/common:santa_cc_proto_library_wrapper",
        "@com_google_absl//absl/status",
        "@com_google_protobuf//src/google/protobuf/json",
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
        "//Source/common:BranchPrediction",
    ],
)

objc_library(
    name = "EndpointSecurityWriterSpool",
    srcs = ["Logs/EndpointSecurity/Writers/Spool.mm"],
    hdrs = ["Logs/EndpointSecurity/Writers/Spool.h"],
    deps = [
        ":EndpointSecurityWriter",
        "//Source/common:SNTLogging",
        "//Source/common:santa_cc_proto_library_wrapper",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:fsspool",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:fsspool_log_batch_writer",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "EndpointSecurityWriterNull",
    srcs = ["Logs/EndpointSecurity/Writers/Null.mm"],
    hdrs = ["Logs/EndpointSecurity/Writers/Null.h"],
    deps = [
        ":EndpointSecurityWriter",
    ],
)

objc_library(
    name = "EndpointSecurityLogger",
    srcs = ["Logs/EndpointSecurity/Logger.mm"],
    hdrs = ["Logs/EndpointSecurity/Logger.h"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerBasicString",
        ":EndpointSecuritySerializerEmpty",
        ":EndpointSecuritySerializerProtobuf",
        ":EndpointSecurityWriter",
        ":EndpointSecurityWriterFile",
        ":EndpointSecurityWriterNull",
        ":EndpointSecurityWriterSpool",
        ":EndpointSecurityWriterSyslog",
        ":SNTDecisionCache",
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
        ":WatchItemPolicy",
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
        ":WatchItemPolicy",
        "//Source/common:Platform",
    ],
)

objc_library(
    name = "SNTDaemonControlController",
    srcs = ["SNTDaemonControlController.mm"],
    hdrs = ["SNTDaemonControlController.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityLogger",
        ":SNTDatabaseController",
        ":SNTEventTable",
        ":SNTNotificationQueue",
        ":SNTPolicyProcessor",
        ":SNTRuleTable",
        ":SNTSyncdQueue",
        ":WatchItems",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTRule",
        "//Source/common:SNTStoredEvent",
        "//Source/common:SNTStrengthify",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "@FMDB",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "Metrics",
    srcs = ["Metrics.mm"],
    hdrs = ["Metrics.h"],
    deps = [
        ":SNTApplicationCoreMetrics",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTXPCMetricServiceInterface",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "Santad",
    srcs = ["Santad.mm"],
    hdrs = ["Santad.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":Metrics",
        ":SNTCompilerController",
        ":SNTDaemonControlController",
        ":SNTDecisionCache",
        ":SNTEndpointSecurityAuthorizer",
        ":SNTEndpointSecurityDeviceManager",
        ":SNTEndpointSecurityFileAccessAuthorizer",
        ":SNTEndpointSecurityRecorder",
        ":SNTEndpointSecurityTamperResistance",
        ":SNTExecutionController",
        ":SNTNotificationQueue",
        ":SNTSyncdQueue",
        ":TTYWriter",
        ":WatchItems",
        "//Source/common:PrefixTree",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileAccessEvent",
        "//Source/common:SNTKVOManager",
        "//Source/common:SNTLogging",
        "//Source/common:SNTXPCNotifierInterface",
        "//Source/common:SNTXPCSyncServiceInterface",
        "//Source/common:Unit",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "SantadDeps",
    srcs = ["SantadDeps.mm"],
    hdrs = ["SantadDeps.h"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityAPI",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":Metrics",
        ":SNTCompilerController",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTEventTable",
        ":SNTExecutionController",
        ":SNTNotificationQueue",
        ":SNTRuleTable",
        ":SNTSyncdQueue",
        ":TTYWriter",
        ":WatchItems",
        "//Source/common:PrefixTree",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SNTXPCUnprivilegedControlInterface",
        "//Source/common:Unit",
        "@MOLXPCConnection",
    ],
)

objc_library(
    name = "santad_main",
    srcs = ["main.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    sdk_frameworks = [
        "DiskArbitration",
    ],
    deps = [
        ":SNTDaemonControlController",
        ":Santad",
        ":SantadDeps",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTLogging",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTXPCControlInterface",
        "//Source/common:SystemResources",
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
    minimum_os_version = "11.0",
    provisioning_profile = select({
        "//:adhoc_build": None,
        "//conditions:default": "//profiles:daemon_dev",
    }),
    version = "//:version",
    visibility = ["//:santa_package_group"],
    deps = [":santad_main"],
)

#
# Begin test targets
#

objc_library(
    name = "MockEndpointSecurityAPI",
    testonly = 1,
    hdrs = ["EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        ":WatchItemPolicy",
        "@com_google_googletest//:gtest",
    ],
)

objc_library(
    name = "MockLogger",
    testonly = 1,
    hdrs = ["Logs/EndpointSecurity/MockLogger.h"],
    deps = [
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        "@com_google_googletest//:gtest",
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
        "//Source/common:Platform",
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
    name = "SantadTest",
    srcs = ["SantadTest.mm"],
    data = [
        "//Source/santad/testdata:binaryrules_testdata",
    ],
    minimum_os_version = "11.0",
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    sdk_frameworks = [
        "DiskArbitration",
    ],
    tags = ["exclusive"],
    deps = [
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTEndpointSecurityAuthorizer",
        ":SantadDeps",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTConfigurator",
        "//Source/common:TestUtils",
        "@MOLCertificate",
        "@MOLCodesignChecker",
        "@OCMock",
        "@com_google_googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTApplicationCoreMetricsTest",
    srcs = [
        "SNTApplicationCoreMetricsTest.mm",
    ],
    minimum_os_version = "11.0",
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
    name = "EndpointSecuritySanitizableStringTest",
    srcs = ["Logs/EndpointSecurity/Serializers/SanitizableStringTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecuritySanitizableString",
        "//Source/common:TestUtils",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerUtilitiesTest",
    srcs = ["Logs/EndpointSecurity/Serializers/UtilitiesTest.mm"],
    deps = [
        ":EndpointSecurityMessage",
        ":EndpointSecuritySerializerUtilities",
        ":MockEndpointSecurityAPI",
        "//Source/common:TestUtils",
        "@OCMock",
        "@com_google_googletest//:gtest",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerBasicStringTest",
    srcs = ["Logs/EndpointSecurity/Serializers/BasicStringTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityMessage",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerBasicString",
        ":MockEndpointSecurityAPI",
        ":SNTDecisionCache",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTStoredEvent",
        "//Source/common:TestUtils",
        "@OCMock",
        "@com_google_googletest//:gtest",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerProtobufTest",
    srcs = ["Logs/EndpointSecurity/Serializers/ProtobufTest.mm"],
    data = [
        "//Source/santad/testdata:protobuf_json_testdata",
    ],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityMessage",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerProtobuf",
        ":MockEndpointSecurityAPI",
        ":SNTDecisionCache",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTStoredEvent",
        "//Source/common:TestUtils",
        "//Source/common:santa_cc_proto_library_wrapper",
        "@OCMock",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//src/google/protobuf/json",
    ],
)

santa_unit_test(
    name = "AuthResultCacheTest",
    srcs = ["EventProviders/AuthResultCacheTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":AuthResultCache",
        ":MockEndpointSecurityAPI",
        "//Source/common:SantaVnode",
        "//Source/common:TestUtils",
        "@OCMock",
        "@com_google_googletest//:gtest",
    ],
)

santa_unit_test(
    name = "RateLimiterTest",
    srcs = ["EventProviders/RateLimiterTest.mm"],
    deps = [
        ":Metrics",
        ":RateLimiter",
        "//Source/common:SystemResources",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerEmptyTest",
    srcs = ["Logs/EndpointSecurity/Serializers/EmptyTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
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
        "@OCMock",
        "@com_google_googletest//:gtest",
    ],
)

santa_unit_test(
    name = "EndpointSecurityWriterSpoolTest",
    srcs = ["Logs/EndpointSecurity/Writers/SpoolTest.mm"],
    deps = [
        ":EndpointSecurityWriterSpool",
        "//Source/common:TestUtils",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:fsspool",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:fsspool_log_batch_writer",
    ],
)

santa_unit_test(
    name = "EndpointSecurityLoggerTest",
    srcs = ["Logs/EndpointSecurity/LoggerTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":EndpointSecuritySerializer",
        ":EndpointSecuritySerializerBasicString",
        ":EndpointSecuritySerializerEmpty",
        ":EndpointSecuritySerializerProtobuf",
        ":EndpointSecurityWriter",
        ":EndpointSecurityWriterFile",
        ":EndpointSecurityWriterNull",
        ":EndpointSecurityWriterSpool",
        ":EndpointSecurityWriterSyslog",
        ":MockEndpointSecurityAPI",
        "//Source/common:SNTCommonEnums",
        "//Source/common:TestUtils",
        "@OCMock",
        "@com_google_googletest//:gtest",
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
    sdk_dylibs = [
        "bsm",
    ],
    deps = [
        ":EndpointSecurityEnricher",
        "//Source/common:TestUtils",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "EndpointSecurityMessageTest",
    srcs = ["EventProviders/EndpointSecurity/MessageTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        "//Source/common:TestUtils",
        "@OCMock",
        "@com_google_googletest//:gtest",
    ],
)

santa_unit_test(
    name = "MetricsTest",
    srcs = ["MetricsTest.mm"],
    deps = [
        ":Metrics",
        "//Source/common:SNTMetricSet",
        "//Source/common:TestUtils",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTDecisionCacheTest",
    srcs = ["SNTDecisionCacheTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTRuleTable",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTRule",
        "//Source/common:TestUtils",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityClientTest",
    srcs = ["EventProviders/SNTEndpointSecurityClientTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityClient",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        ":SNTEndpointSecurityClient",
        ":WatchItemPolicy",
        "//Source/common:SNTConfigurator",
        "//Source/common:TestUtils",
        "@OCMock",
        "@com_google_googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTExecutionControllerTest",
    srcs = ["SNTExecutionControllerTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
    deps = [
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTEventTable",
        ":SNTExecutionController",
        ":SNTRuleTable",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTRule",
        "//Source/common:TestUtils",
        "@MOLCertificate",
        "@MOLCodesignChecker",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityAuthorizerTest",
    srcs = ["EventProviders/SNTEndpointSecurityAuthorizerTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        ":SNTCompilerController",
        ":SNTEndpointSecurityAuthorizer",
        ":SNTExecutionController",
        "//Source/common:SNTCommonEnums",
        "//Source/common:TestUtils",
        "@OCMock",
        "@com_google_googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityFileAccessAuthorizerTest",
    srcs = ["EventProviders/SNTEndpointSecurityFileAccessAuthorizerTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        ":MockLogger",
        ":SNTDecisionCache",
        ":SNTEndpointSecurityFileAccessAuthorizer",
        ":WatchItemPolicy",
        ":WatchItems",
        "//Source/common:Platform",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:TestUtils",
        "@MOLCertificate",
        "@MOLCodesignChecker",
        "@OCMock",
        "@com_google_googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityTamperResistanceTest",
    srcs = ["EventProviders/SNTEndpointSecurityTamperResistanceTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        ":SNTEndpointSecurityTamperResistance",
        ":WatchItemPolicy",
        "//Source/common:SNTLogging",
        "//Source/common:TestUtils",
        "@OCMock",
        "@com_google_googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityRecorderTest",
    srcs = ["EventProviders/SNTEndpointSecurityRecorderTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityClient",
        ":EndpointSecurityEnrichedTypes",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        ":SNTCompilerController",
        ":SNTEndpointSecurityRecorder",
        "//Source/common:PrefixTree",
        "//Source/common:SNTConfigurator",
        "//Source/common:TestUtils",
        "//Source/common:Unit",
        "@OCMock",
        "@com_google_googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityDeviceManagerTest",
    srcs = ["EventProviders/SNTEndpointSecurityDeviceManagerTest.mm"],
    sdk_dylibs = [
        "bsm",
        "EndpointSecurity",
    ],
    deps = [
        ":AuthResultCache",
        ":DiskArbitrationTestLib",
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        ":Metrics",
        ":MockEndpointSecurityAPI",
        ":SNTEndpointSecurityDeviceManager",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeviceEvent",
        "//Source/common:TestUtils",
        "@OCMock",
        "@com_google_googletest//:gtest",
    ],
)

santa_unit_test(
    name = "SNTCompilerControllerTest",
    srcs = ["SNTCompilerControllerTest.mm"],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
    deps = [
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        ":SNTCompilerController",
        ":SNTDecisionCache",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTFileInfo",
        "//Source/common:TestUtils",
        "@OCMock",
        "@com_google_googletest//:gtest",
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
        ":EndpointSecuritySanitizableStringTest",
        ":EndpointSecuritySerializerBasicStringTest",
        ":EndpointSecuritySerializerEmptyTest",
        ":EndpointSecuritySerializerProtobufTest",
        ":EndpointSecuritySerializerUtilitiesTest",
        ":EndpointSecurityWriterFileTest",
        ":EndpointSecurityWriterSpoolTest",
        ":MetricsTest",
        ":RateLimiterTest",
        ":SNTApplicationCoreMetricsTest",
        ":SNTCompilerControllerTest",
        ":SNTDecisionCacheTest",
        ":SNTEndpointSecurityAuthorizerTest",
        ":SNTEndpointSecurityClientTest",
        ":SNTEndpointSecurityDeviceManagerTest",
        ":SNTEndpointSecurityFileAccessAuthorizerTest",
        ":SNTEndpointSecurityRecorderTest",
        ":SNTEndpointSecurityTamperResistanceTest",
        ":SNTEventTableTest",
        ":SNTExecutionControllerTest",
        ":SNTRuleTableTest",
        ":SantadTest",
        ":WatchItemsTest",
        "//Source/santad/Logs/EndpointSecurity/Writers/FSSpool:fsspool_test",
    ],
    visibility = ["//:santa_package_group"],
)
