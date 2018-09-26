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

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "SNTCachedDecision.h"
#import "SNTCommonEnums.h"
#import "SNTConfigurator.h"
#import "SNTDatabaseController.h"
#import "SNTDriverManager.h"
#import "SNTEventLog.h"
#import "SNTEventTable.h"
#import "SNTLogging.h"
#import "SNTNotificationQueue.h"
#import "SNTPolicyProcessor.h"
#import "SNTRule.h"
#import "SNTRuleTable.h"
#import "SNTStoredEvent.h"
#import "SNTStrengthify.h"
#import "SNTSyncdQueue.h"
#import "SNTXPCBundleServiceInterface.h"
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
@property SNTEventLog *eventLog;
@property SNTDriverManager *driverManager;
@property SNTNotificationQueue *notQueue;
@property SNTSyncdQueue *syncdQueue;
@end

@implementation SNTDaemonControlController

- (instancetype)initWithDriverManager:(SNTDriverManager *)driverManager
                    notificationQueue:(SNTNotificationQueue *)notQueue
                           syncdQueue:(SNTSyncdQueue *)syncdQueue
                             eventLog:(SNTEventLog *)eventLog {
  self = [super init];
  if (self) {
    _policyProcessor = [[SNTPolicyProcessor alloc] initWithRuleTable:
                           [SNTDatabaseController ruleTable]];
    _driverManager = driverManager;
    _notQueue = notQueue;
    _syncdQueue = syncdQueue;
    _eventLog = eventLog;
  }
  return self;
}

#pragma mark Kernel ops

- (void)cacheCounts:(void (^)(uint64_t))reply {
  uint64_t count = [self.driverManager cacheCount];
  reply(count);
}

- (void)cacheBucketCount:(void (^)(NSArray *))reply {
  reply([self.driverManager cacheBucketCount]);
}

- (void)flushCache:(void (^)(BOOL))reply {
  reply([self.driverManager flushCache]);
}

- (void)checkCacheForVnodeID:(santa_vnode_id_t)vnodeID withReply:(void (^)(santa_action_t))reply {
  reply([self.driverManager checkCache:vnodeID]);
}

- (void)driverConnectionEstablished:(void (^)(BOOL))reply {
  reply(self.driverManager.connectionEstablished);
}

#pragma mark Database ops

- (void)databaseRuleCounts:(void (^)(int64_t binary,
                                     int64_t certificate,
                                     int64_t compiler,
                                     int64_t transitive))reply {
  SNTRuleTable *rdb = [SNTDatabaseController ruleTable];
  reply([rdb binaryRuleCount], [rdb certificateRuleCount],
        [rdb compilerRuleCount], [rdb transitiveRuleCount]);
}

- (void)databaseRuleAddRules:(NSArray *)rules
                  cleanSlate:(BOOL)cleanSlate
                       reply:(void (^)(NSError *error))reply {
  SNTRuleTable *ruleTable = [SNTDatabaseController ruleTable];

  // If any rules are added that are not plain whitelist rules, then flush decision cache.
  // In particular, the addition of whitelist compiler rules should cause a cache flush.
  // We also flush cache if a whitelist compiler rule is replaced with a whitelist rule.
  BOOL flushCache = (cleanSlate || [ruleTable addedRulesShouldFlushDecisionCache:rules]);

  NSError *error;
  [ruleTable addRules:rules cleanSlate:cleanSlate error:&error];

  // Whenever we add rules, we can also check for and remove outdated transitive rules.
  [ruleTable removeOutdatedTransitiveRules];

  // The actual cache flushing happens after the new rules have been added to the database.
  if (flushCache) {
    LOGI(@"Flushing decision cache");
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
          certificateSHA256:(NSString *)certificateSHA256
                      reply:(void (^)(SNTEventState))reply {
  reply([self.policyProcessor decisionForFilePath:filePath
                                       fileSHA256:fileSHA256
                                certificateSHA256:certificateSHA256].decision);
}

#pragma mark Config Ops

- (void)watchdogInfo:(void (^)(uint64_t, uint64_t, double, double))reply {
  reply(watchdogCPUEvents, watchdogRAMEvents, watchdogCPUPeak, watchdogRAMPeak);
}

- (void)clientMode:(void (^)(SNTClientMode))reply {
  reply([[SNTConfigurator configurator] clientMode]);
}

- (void)setClientMode:(SNTClientMode)mode reply:(void (^)(void))reply {
  [[SNTConfigurator configurator] setSyncServerClientMode:mode];
  reply();
}

- (void)xsrfToken:(void (^)(NSString *))reply {
  reply(self._syncXsrfToken);
}

- (void)setXsrfToken:(NSString *)token reply:(void (^)(void))reply {
  self._syncXsrfToken = token;
  reply();
}

- (void)fullSyncLastSuccess:(void (^)(NSDate *))reply {
  reply([[SNTConfigurator configurator] fullSyncLastSuccess]);
}

- (void)setFullSyncLastSuccess:(NSDate *)date reply:(void (^)(void))reply {
  [[SNTConfigurator configurator] setFullSyncLastSuccess:date];
  reply();
}

- (void)ruleSyncLastSuccess:(void (^)(NSDate *))reply {
  reply([[SNTConfigurator configurator] ruleSyncLastSuccess]);
}

- (void)setRuleSyncLastSuccess:(NSDate *)date reply:(void (^)(void))reply {
  [[SNTConfigurator configurator] setRuleSyncLastSuccess:date];
  reply();
}

- (void)syncCleanRequired:(void (^)(BOOL))reply {
  reply([[SNTConfigurator configurator] syncCleanRequired]);
}

- (void)setSyncCleanRequired:(BOOL)cleanReqd reply:(void (^)(void))reply {
  [[SNTConfigurator configurator] setSyncCleanRequired:cleanReqd];
  reply();
}

- (void)setWhitelistPathRegex:(NSString *)pattern reply:(void (^)(void))reply {
  NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                      options:0
                                                                        error:NULL];
  [[SNTConfigurator configurator] setSyncServerWhitelistPathRegex:re];
  reply();
}

- (void)setBlacklistPathRegex:(NSString *)pattern reply:(void (^)(void))reply {
  NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                      options:0
                                                                        error:NULL];
  [[SNTConfigurator configurator] setSyncServerBlacklistPathRegex:re];
  reply();
}

- (void)enableBundles:(void (^)(BOOL))reply {
  reply([SNTConfigurator configurator].enableBundles);
}

- (void)setEnableBundles:(BOOL)enableBundles reply:(void (^)(void))reply {
  [[SNTConfigurator configurator] setEnableBundles:enableBundles];
  reply();
}

- (void)enableTransitiveWhitelisting:(void (^)(BOOL))reply {
  reply([SNTConfigurator configurator].enableTransitiveWhitelisting);
}

- (void)setEnableTransitiveWhitelisting:(BOOL)enabled reply:(void (^)(void))reply {
  [[SNTConfigurator configurator] setEnableTransitiveWhitelisting:enabled];
  reply();
}

#pragma mark GUI Ops

- (void)setNotificationListener:(NSXPCListenerEndpoint *)listener {
  // This will leak the underlying NSXPCConnection when "fast user switching" occurs.
  // It is not worth the trouble to fix. Maybe future self will feel differently.
  MOLXPCConnection *c = [[MOLXPCConnection alloc] initClientWithListener:listener];
  c.remoteInterface = [SNTXPCNotifierInterface notifierInterface];
  [c resume];
  self.notQueue.notifierConnection = c;
}

- (void)setBundleNotificationListener:(NSXPCListenerEndpoint *)listener {
  MOLXPCConnection *bs = [[MOLXPCConnection alloc] initClientWithServiceName:@"com.google.santabs"];
  bs.remoteInterface = [SNTXPCBundleServiceInterface bundleServiceInterface];
  [bs resume];
  [[bs remoteObjectProxy] setBundleNotificationListener:listener];
  [bs invalidate];
}

#pragma mark syncd Ops

- (void)setSyncdListener:(NSXPCListenerEndpoint *)listener {
  // Only allow one active syncd connection
  if (self.syncdQueue.syncdConnection) return;
  MOLXPCConnection *c = [[MOLXPCConnection alloc] initClientWithListener:listener];
  c.remoteInterface = [SNTXPCSyncdInterface syncdInterface];
  c.invalidationHandler = ^{
    [self.syncdQueue stopSyncingEvents];
    [self.syncdQueue.syncdConnection invalidate];
    self.syncdQueue.syncdConnection = nil;
    if (self.syncdQueue.invalidationHandler) self.syncdQueue.invalidationHandler();
  };
  c.acceptedHandler = ^{
    [self.syncdQueue startSyncingEvents];
  };
  [c resume];
  self.syncdQueue.syncdConnection = c;
}

- (void)pushNotifications:(void (^)(BOOL))reply {
  [self.syncdQueue.syncdConnection.remoteObjectProxy isFCMListening:^(BOOL response) {
    reply(response);
  }];
}

- (void)postRuleSyncNotificationWithCustomMessage:(NSString *)message reply:(void (^)(void))reply {
  [[self.notQueue.notifierConnection remoteObjectProxy]
      postRuleSyncNotificationWithCustomMessage:message];
  reply();
}

#pragma mark Bundle ops

///
///  This method is only used for santactl's bundleinfo command. For blocked executions, SantaGUI
///  calls on santabs directly.
///
///  Hash a bundle for an event. The SNTBundleHashBlock will be called with nil parameters if a
///  failure or cancellation occurs.
///
///  @param event The event that includes the fileBundlePath to be hashed.
///  @param reply A SNTBundleHashBlock to be executed upon completion or cancellation.
///
///  @note If there is a current NSProgress when called this method will report back it's progress.
///
- (void)hashBundleBinariesForEvent:(SNTStoredEvent *)event
                             reply:(SNTBundleHashBlock)reply {
  MOLXPCConnection *bs =
      [[MOLXPCConnection alloc] initClientWithServiceName:[SNTXPCBundleServiceInterface serviceId]];
  bs.remoteInterface = [SNTXPCBundleServiceInterface bundleServiceInterface];
  [bs resume];
  [[bs remoteObjectProxy] hashBundleBinariesForEvent:event reply:reply];
}

///
///  Used by SantaGUI sync the offending event and potentially all the related events,
///  if the sync server has not seen them before.
///
///  @param event The offending event, fileBundleHash & fileBundleBinaryCount need to be populated.
///  @param relatedEvents Nexted bundle events.
///
- (void)syncBundleEvent:(SNTStoredEvent *)event
          relatedEvents:(NSArray<SNTStoredEvent *> *)events {
  SNTEventTable *eventTable = [SNTDatabaseController eventTable];

  // Delete the event cached by the execution controller.
  [eventTable deleteEventWithId:event.idx];

  // Add the updated event.
  [eventTable addStoredEvent:event];

  // Log all of the generated bundle events.
  [self.eventLog logBundleHashingEvents:events];

  WEAKIFY(self);

  // Sync the updated event. If the sync server needs the related events, add them to the eventTable
  // and upload them too.
  [self.syncdQueue addBundleEvent:event reply:^(SNTBundleEventAction action) {
    STRONGIFY(self);
    switch(action) {
      case SNTBundleEventActionDropEvents:
        break;
      case SNTBundleEventActionStoreEvents:
        [eventTable addStoredEvents:events];
        break;
      case SNTBundleEventActionSendEvents:
        [eventTable addStoredEvents:events];
        [self.syncdQueue addEvents:events isFromBundle:YES];
        break;
    }
  }];
}

@end
