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
#import "SNTCommonEnums.h"
#import "SNTConfigurator.h"
#import "SNTDatabaseController.h"
#import "SNTDriverManager.h"
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

- (void)cacheCounts:(void (^)(uint64_t, uint64_t))reply {
  NSArray<NSNumber *> *counts = [self.driverManager cacheCounts];
  reply([counts[0] unsignedLongLongValue], [counts[1] unsignedLongLongValue]);
}

- (void)flushCache:(void (^)(BOOL))reply {
  reply([self.driverManager flushCacheNonRootOnly:NO]);
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
    [self.driverManager flushCacheNonRootOnly:NO];
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
  LOGI(@"Received new whitelist regex, flushing cache");
  [self.driverManager flushCacheNonRootOnly:NO];
  reply();
}

- (void)setBlacklistPathRegex:(NSString *)pattern reply:(void (^)())reply {
  NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                      options:0
                                                                        error:NULL];
  [[SNTConfigurator configurator] setBlacklistPathRegex:re];
  LOGI(@"Received new blacklist regex, flushing cache");
  [self.driverManager flushCacheNonRootOnly:NO];
  reply();
}

- (void)bundlesEnabled:(void (^)(BOOL))reply {
  reply([SNTConfigurator configurator].bundlesEnabled);
}

- (void)setBundlesEnabled:(BOOL)bundlesEnabled reply:(void (^)())reply {
  [[SNTConfigurator configurator] setBundlesEnabled:bundlesEnabled];
  reply();
}

#pragma mark GUI Ops

- (void)setNotificationListener:(NSXPCListenerEndpoint *)listener {
  SNTXPCConnection *c = [[SNTXPCConnection alloc] initClientWithListener:listener];
  c.remoteInterface = [SNTXPCNotifierInterface notifierInterface];
  [c resume];
  self.notQueue.notifierConnection = c;
}

- (void)setBundleNotificationListener:(NSXPCListenerEndpoint *)listener {
  SNTXPCConnection *bs = [[SNTXPCConnection alloc] initClientWithServiceName:@"com.google.santabs"];
  bs.remoteInterface = [SNTXPCBundleServiceInterface bundleServiceInterface];
  [bs resume];
  [[bs remoteObjectProxy] setBundleNotificationListener:listener];
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
  SNTXPCConnection *bs =
      [[SNTXPCConnection alloc] initClientWithServiceName:[SNTXPCBundleServiceInterface serviceId]];
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
