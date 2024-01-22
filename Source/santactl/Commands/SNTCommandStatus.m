/// Copyright 2015-2022 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import <Foundation/Foundation.h>
#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

NSString *StartupOptionToString(SNTDeviceManagerStartupPreferences pref) {
  switch (pref) {
    case SNTDeviceManagerStartupPreferencesUnmount: return @"Unmount";
    case SNTDeviceManagerStartupPreferencesForceUnmount: return @"ForceUnmount";
    case SNTDeviceManagerStartupPreferencesRemount: return @"Remount";
    case SNTDeviceManagerStartupPreferencesForceRemount: return @"ForceRemount";
    default: return @"None";
  }
}

@interface SNTCommandStatus : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandStatus

REGISTER_COMMAND_NAME(@"status")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Show Santa status information.";
}

+ (NSString *)longHelpText {
  return (@"Provides details about Santa while it's running.\n"
          @"  Use --json to output in JSON format");
}

- (void)runWithArguments:(NSArray *)arguments {
  id<SNTDaemonControlXPC> rop = [self.daemonConn synchronousRemoteObjectProxy];

  // Daemon status
  __block NSString *clientMode;
  __block uint64_t cpuEvents, ramEvents;
  __block double cpuPeak, ramPeak;
  [rop clientMode:^(SNTClientMode cm) {
    switch (cm) {
      case SNTClientModeMonitor: clientMode = @"Monitor"; break;
      case SNTClientModeLockdown: clientMode = @"Lockdown"; break;
      default: clientMode = [NSString stringWithFormat:@"Unknown (%ld)", cm]; break;
    }
  }];

  [rop watchdogInfo:^(uint64_t wd_cpuEvents, uint64_t wd_ramEvents, double wd_cpuPeak,
                      double wd_ramPeak) {
    cpuEvents = wd_cpuEvents;
    cpuPeak = wd_cpuPeak;
    ramEvents = wd_ramEvents;
    ramPeak = wd_ramPeak;
  }];

  BOOL fileLogging = ([[SNTConfigurator configurator] fileChangesRegex] != nil);
  NSString *eventLogType = [[[SNTConfigurator configurator] eventLogTypeRaw] lowercaseString];

  SNTConfigurator *configurator = [SNTConfigurator configurator];

  // Cache status
  __block uint64_t rootCacheCount = -1, nonRootCacheCount = -1;
  [rop cacheCounts:^(uint64_t rootCache, uint64_t nonRootCache) {
    rootCacheCount = rootCache;
    nonRootCacheCount = nonRootCache;
  }];

  // Database counts
  __block int64_t eventCount = -1;
  __block int64_t binaryRuleCount = -1;
  __block int64_t certRuleCount = -1;
  __block int64_t teamIDRuleCount = -1;
  __block int64_t signingIDRuleCount = -1;
  __block int64_t compilerRuleCount = -1;
  __block int64_t transitiveRuleCount = -1;
  [rop databaseRuleCounts:^(int64_t binary, int64_t certificate, int64_t compiler,
                            int64_t transitive, int64_t teamID, int64_t signingID) {
    binaryRuleCount = binary;
    certRuleCount = certificate;
    teamIDRuleCount = teamID;
    signingIDRuleCount = signingID;
    compilerRuleCount = compiler;
    transitiveRuleCount = transitive;
  }];
  [rop databaseEventCount:^(int64_t count) {
    eventCount = count;
  }];

  // Static rule count
  __block int64_t staticRuleCount = -1;
  [rop staticRuleCount:^(int64_t count) {
    staticRuleCount = count;
  }];

  // Sync status
  __block NSDate *fullSyncLastSuccess;
  [rop fullSyncLastSuccess:^(NSDate *date) {
    fullSyncLastSuccess = date;
  }];

  __block NSDate *ruleSyncLastSuccess;
  [rop ruleSyncLastSuccess:^(NSDate *date) {
    ruleSyncLastSuccess = date;
  }];

  __block BOOL syncCleanReqd = NO;
  [rop syncCleanRequired:^(BOOL clean) {
    syncCleanReqd = clean;
  }];

  __block BOOL pushNotifications = NO;
  if ([[SNTConfigurator configurator] syncBaseURL]) {
    [rop pushNotifications:^(BOOL response) {
      pushNotifications = response;
    }];
  }

  __block BOOL enableBundles = NO;
  if ([[SNTConfigurator configurator] syncBaseURL]) {
    [rop enableBundles:^(BOOL response) {
      enableBundles = response;
    }];
  }

  __block BOOL enableTransitiveRules = NO;
  [rop enableTransitiveRules:^(BOOL response) {
    enableTransitiveRules = response;
  }];

  __block BOOL watchItemsEnabled = NO;
  __block uint64_t watchItemsRuleCount = 0;
  __block NSString *watchItemsPolicyVersion = nil;
  __block NSString *watchItemsConfigPath = nil;
  __block NSTimeInterval watchItemsLastUpdateEpoch = 0;
  [rop watchItemsState:^(BOOL enabled, uint64_t ruleCount, NSString *policyVersion,
                         NSString *configPath, NSTimeInterval lastUpdateEpoch) {
    watchItemsEnabled = enabled;
    if (enabled) {
      watchItemsRuleCount = ruleCount;
      watchItemsPolicyVersion = policyVersion;
      watchItemsConfigPath = configPath;
      watchItemsLastUpdateEpoch = lastUpdateEpoch;
    }
  }];

  __block BOOL blockUSBMount = NO;
  [rop blockUSBMount:^(BOOL response) {
    blockUSBMount = response;
  }];

  __block NSArray<NSString *> *remountUSBMode;
  [rop remountUSBMode:^(NSArray<NSString *> *response) {
    remountUSBMode = response;
  }];

  // Format dates
  NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
  dateFormatter.dateFormat = @"yyyy/MM/dd HH:mm:ss Z";
  NSString *fullSyncLastSuccessStr = [dateFormatter stringFromDate:fullSyncLastSuccess] ?: @"Never";
  NSString *ruleSyncLastSuccessStr =
    [dateFormatter stringFromDate:ruleSyncLastSuccess] ?: fullSyncLastSuccessStr;

  NSString *watchItemsLastUpdateStr =
    [dateFormatter stringFromDate:[NSDate dateWithTimeIntervalSince1970:watchItemsLastUpdateEpoch]]
      ?: @"Never";

  NSString *syncURLStr = configurator.syncBaseURL.absoluteString;

  BOOL exportMetrics = configurator.exportMetrics;
  NSURL *metricsURLStr = configurator.metricURL;
  NSUInteger metricExportInterval = configurator.metricExportInterval;

  if ([arguments containsObject:@"--json"]) {
    NSMutableDictionary *stats = [@{
      @"daemon" : @{
        @"driver_connected" : @(YES),
        @"mode" : clientMode ?: @"null",
        @"log_type" : eventLogType,
        @"file_logging" : @(fileLogging),
        @"watchdog_cpu_events" : @(cpuEvents),
        @"watchdog_ram_events" : @(ramEvents),
        @"watchdog_cpu_peak" : @(cpuPeak),
        @"watchdog_ram_peak" : @(ramPeak),
        @"block_usb" : @(blockUSBMount),
        @"remount_usb_mode" : (blockUSBMount && remountUSBMode.count ? remountUSBMode : @""),
        @"on_start_usb_options" : StartupOptionToString(configurator.onStartUSBOptions),
      },
      @"database" : @{
        @"binary_rules" : @(binaryRuleCount),
        @"certificate_rules" : @(certRuleCount),
        @"teamid_rules" : @(teamIDRuleCount),
        @"signingid_rules" : @(signingIDRuleCount),
        @"compiler_rules" : @(compilerRuleCount),
        @"transitive_rules" : @(transitiveRuleCount),
        @"events_pending_upload" : @(eventCount),
      },
      @"static_rules" : @{
        @"rule_count" : @(staticRuleCount),
      },
      @"sync" : @{
        @"server" : syncURLStr ?: @"null",
        @"clean_required" : @(syncCleanReqd),
        @"last_successful_full" : fullSyncLastSuccessStr ?: @"null",
        @"last_successful_rule" : ruleSyncLastSuccessStr ?: @"null",
        @"push_notifications" : pushNotifications ? @"Connected" : @"Disconnected",
        @"bundle_scanning" : @(enableBundles),
        @"transitive_rules" : @(enableTransitiveRules),
      },
    } mutableCopy];

    NSDictionary *watchItems;
    if (watchItemsEnabled) {
      watchItems = @{
        @"enabled" : @(watchItemsEnabled),
        @"rule_count" : @(watchItemsRuleCount),
        @"policy_version" : watchItemsPolicyVersion,
        @"config_path" : watchItemsConfigPath ?: @"null",
        @"last_policy_update" : watchItemsLastUpdateStr ?: @"null",
      };
    } else {
      watchItems = @{
        @"enabled" : @(watchItemsEnabled),
      };
    }
    stats[@"watch_items"] = watchItems;

    stats[@"cache"] = @{
      @"root_cache_count" : @(rootCacheCount),
      @"non_root_cache_count" : @(nonRootCacheCount),
    };

    NSData *statsData = [NSJSONSerialization dataWithJSONObject:stats
                                                        options:NSJSONWritingPrettyPrinted
                                                          error:nil];
    NSString *statsStr = [[NSString alloc] initWithData:statsData encoding:NSUTF8StringEncoding];
    printf("%s\n", [statsStr UTF8String]);
  } else {
    printf(">>> Daemon Info\n");
    printf("  %-25s | %s\n", "Mode", [clientMode UTF8String]);

    if (enableTransitiveRules) {
      printf("  %-25s | %s\n", "Transitive Rules", (enableTransitiveRules ? "Yes" : "No"));
    }

    printf("  %-25s | %s\n", "Log Type", [eventLogType UTF8String]);
    printf("  %-25s | %s\n", "File Logging", (fileLogging ? "Yes" : "No"));
    printf("  %-25s | %s\n", "USB Blocking", (blockUSBMount ? "Yes" : "No"));
    if (blockUSBMount && remountUSBMode.count > 0) {
      printf("  %-25s | %s\n", "USB Remounting Mode",
             [[remountUSBMode componentsJoinedByString:@", "] UTF8String]);
    }
    printf("  %-25s | %s\n", "On Start USB Options",
           StartupOptionToString(configurator.onStartUSBOptions).UTF8String);
    printf("  %-25s | %lld  (Peak: %.2f%%)\n", "Watchdog CPU Events", cpuEvents, cpuPeak);
    printf("  %-25s | %lld  (Peak: %.2fMB)\n", "Watchdog RAM Events", ramEvents, ramPeak);

    printf(">>> Cache Info\n");
    printf("  %-25s | %lld\n", "Root cache count", rootCacheCount);
    printf("  %-25s | %lld\n", "Non-root cache count", nonRootCacheCount);

    printf(">>> Database Info\n");
    printf("  %-25s | %lld\n", "Binary Rules", binaryRuleCount);
    printf("  %-25s | %lld\n", "Certificate Rules", certRuleCount);
    printf("  %-25s | %lld\n", "TeamID Rules", teamIDRuleCount);
    printf("  %-25s | %lld\n", "SigningID Rules", signingIDRuleCount);
    printf("  %-25s | %lld\n", "Compiler Rules", compilerRuleCount);
    printf("  %-25s | %lld\n", "Transitive Rules", transitiveRuleCount);
    printf("  %-25s | %lld\n", "Events Pending Upload", eventCount);

    if ([SNTConfigurator configurator].staticRules.count) {
      printf(">>> Static Rules\n");
      printf("  %-25s | %lld\n", "Rules", staticRuleCount);
    }

    printf(">>> Watch Items\n");
    printf("  %-25s | %s\n", "Enabled", (watchItemsEnabled ? "Yes" : "No"));
    if (watchItemsEnabled) {
      printf("  %-25s | %s\n", "Policy Version", watchItemsPolicyVersion.UTF8String);
      printf("  %-25s | %llu\n", "Rule Count", watchItemsRuleCount);
      printf("  %-25s | %s\n", "Config Path", (watchItemsConfigPath ?: @"(embedded)").UTF8String);
      printf("  %-25s | %s\n", "Last Policy Update", watchItemsLastUpdateStr.UTF8String);
    }

    if (syncURLStr) {
      printf(">>> Sync Info\n");
      printf("  %-25s | %s\n", "Sync Server", [syncURLStr UTF8String]);
      printf("  %-25s | %s\n", "Clean Sync Required", (syncCleanReqd ? "Yes" : "No"));
      printf("  %-25s | %s\n", "Last Successful Full Sync", [fullSyncLastSuccessStr UTF8String]);
      printf("  %-25s | %s\n", "Last Successful Rule Sync", [ruleSyncLastSuccessStr UTF8String]);
      printf("  %-25s | %s\n", "Push Notifications",
             (pushNotifications ? "Connected" : "Disconnected"));
      printf("  %-25s | %s\n", "Bundle Scanning", (enableBundles ? "Yes" : "No"));
    }

    if (exportMetrics) {
      printf(">>> Metrics Info\n");
      printf("  %-25s | %s\n", "Metrics Server", [[metricsURLStr absoluteString] UTF8String]);
      printf("  %-25s | %lu\n", "Export Interval (seconds)", metricExportInterval);
    }
  }

  exit(0);
}

@end
