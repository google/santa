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

#import "SNTCommandController.h"

#import "SNTConfigurator.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@interface SNTCommandStatus : NSObject<SNTCommand>
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

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  dispatch_group_t group = dispatch_group_create();

  // Daemon status
  __block NSString *clientMode;
  __block uint64_t cpuEvents, ramEvents;
  __block double cpuPeak, ramPeak;
  dispatch_group_enter(group);
  [[daemonConn remoteObjectProxy] clientMode:^(SNTClientMode cm) {
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
  [[daemonConn remoteObjectProxy] watchdogInfo:^(uint64_t wd_cpuEvents, uint64_t wd_ramEvents,
                                                 double wd_cpuPeak, double wd_ramPeak) {
    cpuEvents = wd_cpuEvents;
    cpuPeak = wd_cpuPeak;
    ramEvents = wd_ramEvents;
    ramPeak = wd_ramPeak;
    dispatch_group_leave(group);
  }];

  BOOL fileLogging = ([[SNTConfigurator configurator] fileChangesRegex] != nil);

  // Kext status
  __block int64_t cacheCount = -1;
  dispatch_group_enter(group);
  [[daemonConn remoteObjectProxy] cacheCount:^(int64_t count) {
    cacheCount = count;
    dispatch_group_leave(group);
  }];

  // Database counts
  __block int64_t eventCount = -1, binaryRuleCount = -1, certRuleCount = -1;
  dispatch_group_enter(group);
  [[daemonConn remoteObjectProxy] databaseRuleCounts:^(int64_t binary, int64_t certificate) {
    binaryRuleCount = binary;
    certRuleCount = certificate;
    dispatch_group_leave(group);
  }];
  dispatch_group_enter(group);
  [[daemonConn remoteObjectProxy] databaseEventCount:^(int64_t count) {
    eventCount = count;
    dispatch_group_leave(group);
  }];

  // Sync status
  NSString *syncURLStr = [[[SNTConfigurator configurator] syncBaseURL] absoluteString];
  NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
  dateFormatter.dateFormat = @"yyyy/MM/dd HH:mm:ss Z";
  NSDate *lastSyncSuccess = [[SNTConfigurator configurator] syncLastSuccess];
  NSString *lastSyncSuccessStr = [dateFormatter stringFromDate:lastSyncSuccess] ?: @"Never";
  BOOL syncCleanReqd = [[SNTConfigurator configurator] syncCleanRequired];

  // Wait a maximum of 5s for stats collected from daemon to arrive.
  if (dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 5))) {
    fprintf(stderr, "Failed to retrieve some stats from daemon\n\n");
  }

  if ([arguments containsObject:@"--json"]) {
    NSDictionary *stats = @{
      @"daemon" : @{
        @"mode" : clientMode,
        @"file_logging" : @(fileLogging),
        @"watchdog_cpu_events" : @(cpuEvents),
        @"watchdog_ram_events" : @(ramEvents),
        @"watchdog_cpu_peak" : @(cpuPeak),
        @"watchdog_ram_peak" : @(ramPeak),
      },
      @"kernel" : @{
        @"cache_count" : @(cacheCount),
      },
      @"database" : @{
        @"binary_rules" : @(binaryRuleCount),
        @"certificate_rules" : @(certRuleCount),
        @"events_pending_upload" : @(eventCount),
      },
      @"sync" : @{
        @"server" : syncURLStr,
        @"clean_required" : @(syncCleanReqd),
        @"last_successful" : lastSyncSuccessStr
      },
    };
    NSData *statsData = [NSJSONSerialization dataWithJSONObject:stats
                                                        options:NSJSONWritingPrettyPrinted
                                                          error:nil];
    NSString *statsStr = [[NSString alloc] initWithData:statsData encoding:NSUTF8StringEncoding];
    printf("%s\n", [statsStr UTF8String]);
  } else {
    printf(">>> Daemon Info\n");
    printf("  %-22s | %s\n", "Mode", [clientMode UTF8String]);
    printf("  %-22s | %s\n", "File Logging", (fileLogging ? "Yes" : "No"));
    printf("  %-22s | %lld  (Peak: %.2f%%)\n", "Watchdog CPU Events", cpuEvents, cpuPeak);
    printf("  %-22s | %lld  (Peak: %.2fMB)\n", "Watchdog RAM Events", ramEvents, ramPeak);
    printf(">>> Kernel Info\n");
    printf("  %-22s | %lld\n", "Kernel cache count", cacheCount);
    printf(">>> Database Info\n");
    printf("  %-22s | %lld\n", "Binary Rules", binaryRuleCount);
    printf("  %-22s | %lld\n", "Certificate Rules", certRuleCount);
    printf("  %-22s | %lld\n", "Events Pending Upload", eventCount);

    if (syncURLStr) {
      printf(">>> Sync Info\n");
      printf("  %-22s | %s\n", "Sync Server", [syncURLStr UTF8String]);
      printf("  %-22s | %s\n", "Clean Sync Required", (syncCleanReqd ? "Yes" : "No"));
      printf("  %-22s | %s\n", "Last Successful Sync", [lastSyncSuccessStr UTF8String]);
    }
  }

  exit(0);
}

@end
