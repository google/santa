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
  return nil;
}

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  dispatch_group_t group = dispatch_group_create();

  // Daemon status
  __block NSString *clientMode;
  __block uint64_t cpuEvents, ramEvents;
  dispatch_group_enter(group);
  [[daemonConn remoteObjectProxy] clientMode:^(santa_clientmode_t cm) {
      switch (cm) {
        case CLIENTMODE_MONITOR:
          clientMode = @"Monitor"; break;
        case CLIENTMODE_LOCKDOWN:
          clientMode = @"Lockdown"; break;
        default:
          clientMode = [NSString stringWithFormat:@"Unknown (%d)", cm]; break;
      }
      dispatch_group_leave(group);
  }];
  dispatch_group_enter(group);
  [[daemonConn remoteObjectProxy] watchdogCPUEvents:^(uint64_t events) {
    cpuEvents = events;
    dispatch_group_leave(group);
  }];
  dispatch_group_enter(group);
  [[daemonConn remoteObjectProxy] watchdogRAMEvents:^(uint64_t events) {
    ramEvents = events;
    dispatch_group_leave(group);
  }];
  char *fileLogging = ([[SNTConfigurator configurator] fileChangesRegex] ? "Enabled" : "Disabled");

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
  dateFormatter.dateFormat = @"YYYY/MM/dd HH:mm:ss z";
  NSDate *lastSyncSuccess = [[SNTConfigurator configurator] syncLastSuccess];
  NSString *lastSyncSuccessStr = [dateFormatter stringFromDate:lastSyncSuccess] ?: @"Never";
  char *syncCleanReqd = [[SNTConfigurator configurator] syncCleanRequired] ? "Yes" : "No";

  // Wait a maximum of 5s for stats collected from daemon to arrive.
  if (dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 5))) {
    printf("Failed to retrieve some stats from daemon\n\n");
  }

  printf(">>> Daemon Info\n");
  printf("  %-22s | %s\n", "Mode", [clientMode UTF8String]);
  printf("  %-22s | %s\n", "File Logging", fileLogging);
  printf("  %-22s | %lld\n", "Watchdog CPU Events", cpuEvents);
  printf("  %-22s | %lld\n", "Watchdog RAM Events", ramEvents);
  printf(">>> Kernel Info\n");
  printf("  %-22s | %lld\n", "Kernel cache count", cacheCount);
  printf(">>> Database Info\n");
  printf("  %-22s | %lld\n", "Binary Rules", binaryRuleCount);
  printf("  %-22s | %lld\n", "Certificate Rules", certRuleCount);
  printf("  %-22s | %lld\n", "Events Pending Upload", eventCount);

  if (syncURLStr) {
    printf(">>> Sync Info\n");
    printf("  %-22s | %s\n", "Sync Server", [syncURLStr UTF8String]);
    printf("  %-22s | %s\n", "Clean Sync Required", syncCleanReqd);
    printf("  %-22s | %s\n", "Last Successful Sync", [lastSyncSuccessStr UTF8String]);
  }

  exit(0);
}

@end
