/// Copyright 2015 Google Inc. All rights reserved.
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

@import Foundation;

#import "SNTCommand.h"
#import "SNTCommandController.h"

#import "SNTConfigurator.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@interface SNTCommandStatus : SNTCommand<SNTCommandProtocol>
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
  dispatch_group_t group = dispatch_group_create();

  // Daemon status
  __block NSString *clientMode;
  __block uint64_t cpuEvents, ramEvents;
  __block double cpuPeak, ramPeak;
  dispatch_group_enter(group);
  [[self.daemonConn remoteObjectProxy] clientMode:^(SNTClientMode cm) {
    switch (cm) {
      case SNTClientModeMonitor:
        clientMode = @"Monitor";
        break;
      case SNTClientModeLockdown:
        clientMode = @"Lockdown";
        break;
      default:
        clientMode = [NSString stringWithFormat:@"Unknown (%ld)", cm];
        break;
    }
    dispatch_group_leave(group);
  }];
  dispatch_group_enter(group);
  [[self.daemonConn remoteObjectProxy] watchdogInfo:^(uint64_t wd_cpuEvents, uint64_t wd_ramEvents,
                                                      double wd_cpuPeak, double wd_ramPeak) {
    cpuEvents = wd_cpuEvents;
    cpuPeak = wd_cpuPeak;
    ramEvents = wd_ramEvents;
    ramPeak = wd_ramPeak;
    dispatch_group_leave(group);
  }];

  BOOL fileLogging = ([[SNTConfigurator configurator] fileChangesRegex] != nil);

  // Kext status
  __block uint64_t rootCacheCount = -1, nonRootCacheCount = -1;
  dispatch_group_enter(group);
  [[self.daemonConn remoteObjectProxy] cacheCounts:^(uint64_t rootCache, uint64_t nonRootCache) {
    rootCacheCount = rootCache;
    nonRootCacheCount = nonRootCache;
    dispatch_group_leave(group);
  }];

  // Database counts
  __block int64_t eventCount = -1, binaryRuleCount = -1, certRuleCount = -1;
  dispatch_group_enter(group);
  [[self.daemonConn remoteObjectProxy] databaseRuleCounts:^(int64_t binary, int64_t certificate) {
    binaryRuleCount = binary;
    certRuleCount = certificate;
    dispatch_group_leave(group);
  }];
  dispatch_group_enter(group);
  [[self.daemonConn remoteObjectProxy] databaseEventCount:^(int64_t count) {
    eventCount = count;
    dispatch_group_leave(group);
  }];

  // Sync status
  NSString *syncURLStr = [[[SNTConfigurator configurator] syncBaseURL] absoluteString];
  NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
  dateFormatter.dateFormat = @"yyyy/MM/dd HH:mm:ss Z";
  NSDate *lastSyncSuccess = [[SNTConfigurator configurator] fullSyncLastSuccess];
  NSString *lastSyncSuccessStr = [dateFormatter stringFromDate:lastSyncSuccess] ?: @"Never";
  NSDate *lastRuleSyncSuccess = [[SNTConfigurator configurator] ruleSyncLastSuccess];
  NSString *lastRuleSyncSuccessStr =
      [dateFormatter stringFromDate:lastRuleSyncSuccess] ?: lastSyncSuccessStr;
  BOOL syncCleanReqd = [[SNTConfigurator configurator] syncCleanRequired];

  __block BOOL pushNotifications = NO;
  if ([[SNTConfigurator configurator] syncBaseURL]) {
    dispatch_group_enter(group);
    [[self.daemonConn remoteObjectProxy] pushNotifications:^(BOOL response) {
      pushNotifications = response;
      dispatch_group_leave(group);
    }];
  }

  __block BOOL bundlesEnabled = NO;
  if ([[SNTConfigurator configurator] syncBaseURL]) {
    dispatch_group_enter(group);
    [[self.daemonConn remoteObjectProxy] bundlesEnabled:^(BOOL response) {
      bundlesEnabled = response;
      dispatch_group_leave(group);
    }];
  }

  // Wait a maximum of 5s for stats collected from daemon to arrive.
  if (dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 5))) {
    fprintf(stderr, "Failed to retrieve some stats from daemon\n\n");
  }

  if ([arguments containsObject:@"--json"]) {
    NSDictionary *stats = @{
      @"daemon" : @{
        @"mode" : clientMode ?: @"null",
        @"file_logging" : @(fileLogging),
        @"watchdog_cpu_events" : @(cpuEvents),
        @"watchdog_ram_events" : @(ramEvents),
        @"watchdog_cpu_peak" : @(cpuPeak),
        @"watchdog_ram_peak" : @(ramPeak),
      },
      @"kernel" : @{
        @"root_cache_count" : @(rootCacheCount),
        @"non_root_cache_count": @(nonRootCacheCount),
      },
      @"database" : @{
        @"binary_rules" : @(binaryRuleCount),
        @"certificate_rules" : @(certRuleCount),
        @"events_pending_upload" : @(eventCount),
      },
      @"sync" : @{
        @"server" : syncURLStr ?: @"null",
        @"clean_required" : @(syncCleanReqd),
        @"last_successful_full" : lastSyncSuccessStr ?: @"null",
        @"last_successful_rule" : lastRuleSyncSuccessStr ?: @"null",
        @"push_notifications" : pushNotifications ? @"Connected" : @"Disconnected",
        @"bundle_scanning" : @(bundlesEnabled)
      },
    };
    NSData *statsData = [NSJSONSerialization dataWithJSONObject:stats
                                                        options:NSJSONWritingPrettyPrinted
                                                          error:nil];
    NSString *statsStr = [[NSString alloc] initWithData:statsData encoding:NSUTF8StringEncoding];
    printf("%s\n", [statsStr UTF8String]);
  } else {
    printf(">>> Daemon Info\n");
    printf("  %-25s | %s\n", "Mode", [clientMode UTF8String]);
    printf("  %-25s | %s\n", "File Logging", (fileLogging ? "Yes" : "No"));
    printf("  %-25s | %lld  (Peak: %.2f%%)\n", "Watchdog CPU Events", cpuEvents, cpuPeak);
    printf("  %-25s | %lld  (Peak: %.2fMB)\n", "Watchdog RAM Events", ramEvents, ramPeak);
    printf(">>> Kernel Info\n");
    printf("  %-25s | %lld\n", "Root cache count", rootCacheCount);
    printf("  %-25s | %lld\n", "Non-root cache count", nonRootCacheCount);
    printf(">>> Database Info\n");
    printf("  %-25s | %lld\n", "Binary Rules", binaryRuleCount);
    printf("  %-25s | %lld\n", "Certificate Rules", certRuleCount);
    printf("  %-25s | %lld\n", "Events Pending Upload", eventCount);

    if (syncURLStr) {
      printf(">>> Sync Info\n");
      printf("  %-25s | %s\n", "Sync Server", [syncURLStr UTF8String]);
      printf("  %-25s | %s\n", "Clean Sync Required", (syncCleanReqd ? "Yes" : "No"));
      printf("  %-25s | %s\n", "Last Successful Full Sync", [lastSyncSuccessStr UTF8String]);
      printf("  %-25s | %s\n", "Last Successful Rule Sync", [lastRuleSyncSuccessStr UTF8String]);
      printf("  %-25s | %s\n", "Push Notifications",
             (pushNotifications ? "Connected" : "Disconnected"));
      printf("  %-25s | %s\n", "Bundle Scanning", (bundlesEnabled ? "Yes" : "No"));
    }
  }

  exit(0);
}

@end
