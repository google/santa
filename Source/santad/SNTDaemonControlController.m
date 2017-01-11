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

#import "SNTCachedDecision.h"
#import "SNTConfigurator.h"
#import "SNTDatabaseController.h"
#import "SNTDriverManager.h"
#import "SNTEventTable.h"
#import "SNTLogging.h"
#import "SNTNotificationQueue.h"
#import "SNTPolicyProcessor.h"
#import "SNTRule.h"
#import "SNTRuleTable.h"
#import "SNTSyncdQueue.h"
#import "SNTXPCConnection.h"
#import "SNTXPCNotifierInterface.h"
#import "SNTXPCSyncdInterface.h"

// Globals used by the santad watchdog thread
uint64_t watchdogCPUEvents = 0;
uint64_t watchdogRAMEvents = 0;
double watchdogCPUPeak = 0;
double watchdogRAMPeak = 0;

@interface SNTDaemonControlController ()
@property NSString *_syncXsrfToken;
@property SNTPolicyProcessor *policyProcessor;
@end

@implementation SNTDaemonControlController

- (instancetype)init {
  self = [super init];
  if (self) {
    _policyProcessor = [[SNTPolicyProcessor alloc] initWithRuleTable:
                           [SNTDatabaseController ruleTable]];
  }
  return self;
}

#pragma mark Kernel ops

- (void)cacheCount:(void (^)(int64_t))reply {
  int64_t count = [self.driverManager cacheCount];
  reply(count);
}

- (void)flushCache:(void (^)(BOOL))reply {
  reply([self.driverManager flushCache]);
}

- (void)checkCacheForVnodeID:(uint64_t)vnodeID withReply:(void (^)(santa_action_t))reply {
  reply([self.driverManager checkCache:vnodeID]);
}

#pragma mark Database ops

- (void)databaseRuleCounts:(void (^)(int64_t binary, int64_t certificate))reply {
  SNTRuleTable *rdb = [SNTDatabaseController ruleTable];
  reply([rdb binaryRuleCount], [rdb certificateRuleCount]);
}

- (void)databaseRuleAddRules:(NSArray *)rules
                  cleanSlate:(BOOL)cleanSlate
                       reply:(void (^)(NSError *error))reply {
  NSError *error;
  [[SNTDatabaseController ruleTable] addRules:rules cleanSlate:cleanSlate error:&error];

  // If any rules were added that were not whitelist, flush cache.
  NSPredicate *p = [NSPredicate predicateWithFormat:@"SELF.state != %d", SNTRuleStateWhitelist];
  if ([rules filteredArrayUsingPredicate:p].count || cleanSlate) {
    LOGI(@"Received non-whitelist rule, flushing cache");
    [self.driverManager flushCache];
  }

  reply(error);
}

- (void)databaseEventCount:(void (^)(int64_t count))reply {
  reply([[SNTDatabaseController eventTable] pendingEventsCount]);
}

- (void)databaseEventsPending:(void (^)(NSArray *events))reply {
  reply([[SNTDatabaseController eventTable] pendingEvents]);
}

- (void)databaseRemoveEventsWithIDs:(NSArray *)ids {
  [[SNTDatabaseController eventTable] deleteEventsWithIds:ids];
}

- (void)databaseRuleForBinarySHA256:(NSString *)binarySHA256
                  certificateSHA256:(NSString *)certificateSHA256
                              reply:(void (^)(SNTRule *))reply {
  reply([[SNTDatabaseController ruleTable] ruleForBinarySHA256:binarySHA256
                                             certificateSHA256:certificateSHA256]);
}

#pragma mark Decision Ops

- (void)decisionForFilePath:(NSString *)filePath
                 fileSHA256:(NSString *)fileSHA256
         signingCertificate:(MOLCertificate *)signingCertificate
                      reply:(void (^)(SNTEventState))reply {
  reply([self.policyProcessor decisionForFilePath:filePath
                                       fileSHA256:fileSHA256
                               signingCertificate:signingCertificate].decision);
}

#pragma mark Config Ops

- (void)clientMode:(void (^)(SNTClientMode))reply {
  reply([[SNTConfigurator configurator] clientMode]);
}

- (void)setClientMode:(SNTClientMode)mode reply:(void (^)())reply {
  if ([[SNTConfigurator configurator] clientMode] != mode) {
    [[SNTConfigurator configurator] setClientMode:mode];
    [[self.notQueue.notifierConnection remoteObjectProxy] postClientModeNotification:mode];
  }
  reply();
}

- (void)xsrfToken:(void (^)(NSString *))reply {
  reply(self._syncXsrfToken);
}

- (void)setXsrfToken:(NSString *)token reply:(void (^)())reply {
  self._syncXsrfToken = token;
  reply();
}

- (void)setSyncLastSuccess:(NSDate *)date reply:(void (^)())reply {
  [[SNTConfigurator configurator] setFullSyncLastSuccess:date];
  reply();
}

- (void)setRuleSyncLastSuccess:(NSDate *)date reply:(void (^)())reply {
  [[SNTConfigurator configurator] setRuleSyncLastSuccess:date];
  reply();
}

- (void)setSyncCleanRequired:(BOOL)cleanReqd reply:(void (^)())reply {
  [[SNTConfigurator configurator] setSyncCleanRequired:cleanReqd];
  reply();
}

- (void)setWhitelistPathRegex:(NSString *)pattern reply:(void (^)())reply {
  NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                      options:0
                                                                        error:NULL];
  [[SNTConfigurator configurator] setWhitelistPathRegex:re];
  reply();
}

- (void)setBlacklistPathRegex:(NSString *)pattern reply:(void (^)())reply {
  NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                      options:0
                                                                        error:NULL];
  [[SNTConfigurator configurator] setBlacklistPathRegex:re];
  reply();
}

- (void)watchdogInfo:(void (^)(uint64_t, uint64_t, double, double))reply {
  reply(watchdogCPUEvents, watchdogRAMEvents, watchdogCPUPeak, watchdogRAMPeak);
}

#pragma mark GUI Ops

- (void)setNotificationListener:(NSXPCListenerEndpoint *)listener {
  SNTXPCConnection *c = [[SNTXPCConnection alloc] initClientWithListener:listener];
  c.remoteInterface = [SNTXPCNotifierInterface notifierInterface];
  [c resume];
  self.notQueue.notifierConnection = c;
}

#pragma mark syncd Ops

- (void)setSyncdListener:(NSXPCListenerEndpoint *)listener {
  // Only allow one active syncd connection
  if (self.syncdQueue.syncdConnection) return;
  SNTXPCConnection *c = [[SNTXPCConnection alloc] initClientWithListener:listener];
  c.remoteInterface = [SNTXPCSyncdInterface syncdInterface];
  c.invalidationHandler = ^{
    [self.syncdQueue stopSyncingEvents];
    self.syncdQueue.syncdConnection = nil;
    self.syncdQueue.invalidationHandler();
  };
  c.acceptedHandler = ^{
    [self.syncdQueue startSyncingEvents];
  };
  [c resume];
  self.syncdQueue.syncdConnection = c;
}

- (void)setNextSyncInterval:(uint64_t)seconds reply:(void (^)())reply {
  [[self.syncdQueue.syncdConnection remoteObjectProxy] rescheduleSyncSecondsFromNow:seconds];
  [[SNTConfigurator configurator] setSyncBackOff:YES];
  reply();
}

- (void)pushNotifications:(void (^)(BOOL))reply {
  [self.syncdQueue.syncdConnection.remoteObjectProxy isFCMListening:^(BOOL response) {
    reply(response);
  }];
}

- (void)postRuleSyncNotificationWithCustomMessage:(NSString *)message reply:(void (^)())reply {
  [[self.notQueue.notifierConnection remoteObjectProxy]
      postRuleSyncNotificationWithCustomMessage:message];
  reply();
}

@end
