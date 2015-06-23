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

#import "SNTDaemonControlController.h"

#import "SNTConfigurator.h"
#import "SNTDatabaseController.h"
#import "SNTDriverManager.h"
#import "SNTDropRootPrivs.h"
#import "SNTEventTable.h"
#import "SNTLogging.h"
#import "SNTRule.h"
#import "SNTRuleTable.h"

@interface SNTDaemonControlController ()
@property dispatch_source_t syncTimer;
@end

@implementation SNTDaemonControlController

- (instancetype)initWithDriverManager:(SNTDriverManager *)driverManager {
  self = [super init];
  if (self) {
    _driverManager = driverManager;

    _syncTimer = [self createSyncTimer];
    [self rescheduleSyncSecondsFromNow:600];
  }
  return self;
}

- (dispatch_source_t)createSyncTimer {
  dispatch_source_t syncTimerQ = dispatch_source_create(
      DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));

  dispatch_source_set_event_handler(syncTimerQ, ^{
    [self rescheduleSyncSecondsFromNow:600];

    if (![[SNTConfigurator configurator] syncBaseURL]) return;
    [[SNTConfigurator configurator] setSyncBackOff:NO];

    pid_t child = fork();
    if (child == 0) {
      // Ensure we have no privileges
      if (!DropRootPrivileges()) {
        _exit(1);
      }

      _exit(execl(kSantaCtlPath, kSantaCtlPath, "sync", NULL));
    }
  });

  dispatch_resume(syncTimerQ);

  return syncTimerQ;
}

- (void)rescheduleSyncSecondsFromNow:(uint64_t)seconds {
  uint64_t interval = seconds * NSEC_PER_SEC;
  uint64_t leeway = (seconds * 0.05) * NSEC_PER_SEC;
  dispatch_source_set_timer(self.syncTimer, dispatch_walltime(NULL, interval), interval, leeway);
}

#pragma mark Kernel ops

- (void)cacheCount:(void (^)(int64_t))reply {
  int64_t count = [self.driverManager cacheCount];
  reply(count);
}

- (void)flushCache:(void (^)(BOOL))reply {
  reply([self.driverManager flushCache]);
}

#pragma mark Database ops

- (void)databaseRuleCounts:(void (^)(int64_t binary, int64_t certificate))reply {
  SNTRuleTable *rdb = [SNTDatabaseController ruleTable];
  reply([rdb binaryRuleCount], [rdb certificateRuleCount]);
}

- (void)databaseRuleAddRule:(SNTRule *)rule cleanSlate:(BOOL)cleanSlate reply:(void (^)())reply {
  [self databaseRuleAddRules:@[ rule ] cleanSlate:cleanSlate reply:reply];
}

- (void)databaseRuleAddRules:(NSArray *)rules cleanSlate:(BOOL)cleanSlate reply:(void (^)())reply {
  [[SNTDatabaseController ruleTable] addRules:rules cleanSlate:cleanSlate];

  // If any rules were added that were not whitelist, flush cache.
  NSPredicate *p = [NSPredicate predicateWithFormat:@"SELF.state != %d", RULESTATE_WHITELIST];
  if ([rules filteredArrayUsingPredicate:p].count || cleanSlate) {
    LOGI(@"Received non-whitelist rule, flushing cache");
    [self.driverManager flushCache];
  }

  reply();
}

- (void)databaseEventCount:(void (^)(int64_t count))reply {
  reply([[SNTDatabaseController eventTable] pendingEventsCount]);
}

- (void)databaseEventForSHA256:(NSString *)sha256 reply:(void (^)(SNTStoredEvent *))reply {
  reply([[SNTDatabaseController eventTable] pendingEventForSHA256:sha256]);
}

- (void)databaseEventsPending:(void (^)(NSArray *events))reply {
  reply([[SNTDatabaseController eventTable] pendingEvents]);
}

- (void)databaseRemoveEventsWithIDs:(NSArray *)ids {
  [[SNTDatabaseController eventTable] deleteEventsWithIds:ids];
}

#pragma mark Misc

- (void)clientMode:(void (^)(santa_clientmode_t))reply {
  reply([[SNTConfigurator configurator] clientMode]);
}

- (void)setClientMode:(santa_clientmode_t)mode reply:(void (^)())reply {
  [[SNTConfigurator configurator] setClientMode:mode];
  reply();
}

- (void)setNextSyncInterval:(uint64_t)seconds reply:(void (^)())reply {
  [self rescheduleSyncSecondsFromNow:seconds];
  [[SNTConfigurator configurator] setSyncBackOff:YES];
  reply();
}

- (void)setWhitelistPathRegex:(NSString *)pattern reply:(void (^)())reply {
  NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                      options:0
                                                                        error:NULL];
  [[SNTConfigurator configurator] setWhitelistPathRegex:re];
  reply();
}

@end
