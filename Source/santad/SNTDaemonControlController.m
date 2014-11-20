/// Copyright 2014 Google Inc. All rights reserved.
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
#import "SNTEventTable.h"
#import "SNTLogging.h"
#import "SNTRule.h"
#import "SNTRuleTable.h"

@implementation SNTDaemonControlController

- (instancetype)initWithDriverManager:(SNTDriverManager *)driverManager {
  self = [super init];
  if (self) {
    _driverManager = driverManager;
  }
  return self;
}

#pragma mark Kernel ops

- (void)cacheCount:(void (^)(uint64_t))reply; {
  uint64_t count = [self.driverManager cacheCount];
  reply(count);
}

- (void)flushCache:(void (^)(BOOL))reply {
  reply([self.driverManager flushCache]);
}

#pragma mark Database ops

- (void)databaseRuleCounts:(void (^)(uint64_t binary, uint64_t certificate))reply {
  SNTRuleTable *rdb = [SNTDatabaseController ruleTable];
  reply([rdb binaryRuleCount], [rdb certificateRuleCount]);
}

- (void)databaseRuleAddRule:(SNTRule *)rule withReply:(void (^)())reply {
  [[SNTDatabaseController ruleTable] addRule:rule];
  reply();
}

- (void)databaseRuleAddRules:(NSArray *)rules withReply:(void (^)())reply {
  [[SNTDatabaseController ruleTable] addRules:rules];
  reply();
}

- (void)databaseEventCount:(void (^)(uint64_t count))reply {
  reply([[SNTDatabaseController eventTable] eventsPendingCount]);
}

- (void)databaseEventForSHA1:(NSString *)sha1 withReply:(void (^)(SNTStoredEvent *))reply {
  reply([[SNTDatabaseController eventTable] latestEventForSHA1:sha1]);
}

- (void)databaseEventsPending:(void (^)(NSArray *events))reply {
  reply([[SNTDatabaseController eventTable] pendingEvents]);
}

- (void)databaseRemoveEventsWithIDs:(NSArray *)ids {
  [[SNTDatabaseController eventTable] deleteEventsWithIndexes:ids];
}

#pragma mark Misc

- (void)clientMode:(void (^)(santa_clientmode_t))reply {
  reply([[SNTConfigurator configurator] clientMode]);
}

- (void)setClientMode:(santa_clientmode_t)mode withReply:(void (^)())reply {
  [[SNTConfigurator configurator] setClientMode:mode];
  reply();
}

@end
