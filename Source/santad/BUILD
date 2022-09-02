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
    name = "SNTEndpointSecurityEventHandler",
    hdrs = ["EventProviders/SNTEndpointSecurityEventHandler.h"],
    deps = [
        ":EndpointSecurityMessage",
        "//Source/common:SNTCommon",
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
        ":SNTEndpointSecurityEventHandler",
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
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":SNTEndpointSecurityClient",
        ":SNTEndpointSecurityEventHandler",
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
        ":SNTEndpointSecurityClient",
        ":SNTExecutionController",
        ":SNTCompilerController",
        ":SNTEndpointSecurityEventHandler",
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
        ":SNTEndpointSecurityClient",
        ":SNTEndpointSecurityEventHandler",
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
    srcs = ["Logs/EndpointSecurity/Serializers/Serializer.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/Serializer.h"],
    deps = [
        ":EndpointSecurityMessage",
        ":EndpointSecurityEnrichedTypes",
        ":SNTDecisionCache",
    ],
)

objc_library(
    name = "EndpointSecuritySerializerUtilities",
    srcs = ["Logs/EndpointSecurity/Serializers/Utilities.mm"],
    hdrs = ["Logs/EndpointSecurity/Serializers/Utilities.h"],
    deps = [
        ":EndpointSecurityMessage",
        "//Source/common:SNTLogging",
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
        ":EndpointSecuritySerializerUtilities",
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
    srcs = ["SNTDaemonControlController.mm"],
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
    srcs = ["Metrics.mm"],
    hdrs = ["Metrics.h"],
    deps = [
      ":SNTApplicationCoreMetrics",
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
    name = "SantadDeps",
    srcs = ["SantadDeps.mm"],
    hdrs = ["SantadDeps.h"],
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
        ":Santad",
        ":SantadDeps",
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

#
# Begin test targets
#

objc_library(
    name = "MockEndpointSecurityAPI",
    hdrs = ["EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"],
    deps = [
        ":EndpointSecurityAPI",
        "@com_google_googletest//:gtest",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
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
    name = "SantadTest",
    srcs = ["SantadTest.mm"],
    data = [
        "//Source/santad/testdata:binaryrules_testdata",
    ],
    minimum_os_version = "10.15",
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
        ":MockEndpointSecurityAPI",
        ":SantadDeps",
        ":SNTDatabaseController",
        ":SNTEndpointSecurityAuthorizer",
        "//Source/common:SNTConfigurator",
        "//Source/common:TestUtils",
        "@com_google_googletest//:gtest",
        "@MOLCertificate",
        "@MOLCodesignChecker",
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
    name = "EndpointSecuritySerializerUtilitiesTest",
    srcs = ["Logs/EndpointSecurity/Serializers/UtilitiesTest.mm"],
    deps = [
        ":EndpointSecurityAPI",
        ":EndpointSecurityMessage",
        ":EndpointSecuritySerializerUtilities",
        ":MockEndpointSecurityAPI",
        "//Source/common:TestUtils",
        "@com_google_googletest//:gtest",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
)

santa_unit_test(
    name = "EndpointSecuritySerializerBasicStringTest",
    srcs = ["Logs/EndpointSecurity/Serializers/BasicStringTest.mm"],
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
        ":MockEndpointSecurityAPI",
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
    sdk_dylibs = [
        "EndpointSecurity",
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
        ":MockEndpointSecurityAPI",
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
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
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
    name = "MetricsTest",
    srcs = ["MetricsTest.mm"],
    deps = [
        ":Metrics",
        "@OCMock",
    ],
)

santa_unit_test(
    name = "SNTDecisionCacheTest",
    srcs = ["SNTDecisionCacheTest.mm"],
    deps = [
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTRule",
        "//Source/common:TestUtils",
        "@OCMock",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityClientTest",
    srcs = ["EventProviders/SNTEndpointSecurityClientTest.mm"],
    deps = [
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        ":EndpointSecurityEnrichedTypes",
        ":MockEndpointSecurityAPI",
        ":SNTEndpointSecurityClient",
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
    name = "SNTExecutionControllerTest",
    srcs = ["SNTExecutionControllerTest.mm",],
    deps = [
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        ":SNTDatabaseController",
        ":SNTDecisionCache",
        ":SNTExecutionController",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTCommonEnums",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTFileInfo",
        "//Source/common:SNTMetricSet",
        "//Source/common:SNTRule",
        "//Source/common:TestUtils",
        "@OCMock",
        "@MOLCertificate",
        "@MOLCodesignChecker",

    ],
    sdk_dylibs = [
        "EndpointSecurity",
        "bsm",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityAuthorizerTest",
    srcs = ["EventProviders/SNTEndpointSecurityAuthorizerTest.mm"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        ":SNTCompilerController",
        ":SNTEndpointSecurityAuthorizer",
        "//Source/common:TestUtils",
        "@com_google_googletest//:gtest",
        "@OCMock",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityTamperResistanceTest",
    srcs = ["EventProviders/SNTEndpointSecurityTamperResistanceTest.mm"],
    deps = [
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        ":SNTEndpointSecurityTamperResistance",
        "//Source/common:TestUtils",
        "@com_google_googletest//:gtest",
        "@OCMock",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityRecorderTest",
    srcs = ["EventProviders/SNTEndpointSecurityRecorderTest.mm"],
    deps = [
        ":AuthResultCache",
        ":EndpointSecurityClient",
        ":EndpointSecurityEnricher",
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        ":SNTCompilerController",
        ":SNTEndpointSecurityRecorder",
        "//Source/common:TestUtils",
        "@com_google_googletest//:gtest",
        "@OCMock",
    ],
    sdk_dylibs = [
        "EndpointSecurity",
    ],
)

santa_unit_test(
    name = "SNTEndpointSecurityDeviceManagerTest",
    srcs = ["EventProviders/SNTEndpointSecurityDeviceManagerTest.mm"],
    deps = [
        ":DiskArbitrationTestLib",
        ":EndpointSecurityClient",
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        ":SNTEndpointSecurityDeviceManager",
        "//Source/common:SNTConfigurator",
        "//Source/common:SNTDeviceEvent",
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
    name = "SNTCompilerControllerTest",
    srcs = ["SNTCompilerControllerTest.mm"],
    deps = [
        ":EndpointSecurityLogger",
        ":EndpointSecurityMessage",
        ":MockEndpointSecurityAPI",
        ":SNTCompilerController",
        ":SNTDecisionCache",
        "//Source/common:SNTCachedDecision",
        "//Source/common:SNTFileInfo",
        "//Source/common:TestUtils",
        "@com_google_googletest//:gtest",
        "@OCMock",
    ],
    sdk_dylibs = [
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
        ":EndpointSecuritySerializerUtilitiesTest",
        ":EndpointSecurityWriterFileTest",
        ":MetricsTest",
        ":SantadTest",
        ":SNTApplicationCoreMetricsTest",
        ":SNTCompilerControllerTest",
        ":SNTDecisionCacheTest",
        ":SNTEndpointSecurityAuthorizerTest",
        ":SNTEndpointSecurityClientTest",
        ":SNTEndpointSecurityDeviceManagerTest",
        ":SNTEndpointSecurityRecorderTest",
        ":SNTEndpointSecurityTamperResistanceTest",
        ":SNTEventTableTest",
        ":SNTExecutionControllerTest",
        ":SNTRuleTableTest",
    ],
    visibility = ["//:santa_package_group"],
)
