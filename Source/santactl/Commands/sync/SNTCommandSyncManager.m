/// Copyright 2016 Google Inc. All rights reserved.
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

#import "SNTCommandSyncManager.h"

#import <SystemConfiguration/SystemConfiguration.h>

#import <MOLAuthenticatingURLSession/MOLAuthenticatingURLSession.h>
#import <MOLFCMClient/MOLFCMClient.h>
#import <MOLXPCConnection/MOLXPCConnection.h>

#import "SNTConfigurator.h"
#import "SNTCommandSyncConstants.h"
#import "SNTCommandSyncEventUpload.h"
#import "SNTCommandSyncPostflight.h"
#import "SNTCommandSyncPreflight.h"
#import "SNTCommandSyncRuleDownload.h"
#import "SNTCommandSyncState.h"
#import "SNTCommonEnums.h"
#import "SNTLogging.h"
#import "SNTStoredEvent.h"
#import "SNTStrengthify.h"
#import "SNTXPCControlInterface.h"
#import "SNTXPCSyncdInterface.h"

static NSString *const kFCMActionKey = @"action";
static NSString *const kFCMFileHashKey = @"file_hash";
static NSString *const kFCMFileNameKey = @"file_name";
static NSString *const kFCMTargetHostIDKey = @"target_host_id";

@interface SNTCommandSyncManager () {
  SCNetworkReachabilityRef _reachability;
}

@property(nonatomic) dispatch_source_t fullSyncTimer;
@property(nonatomic) dispatch_source_t ruleSyncTimer;

@property(nonatomic) NSCache *dispatchLock;

// whitelistNotifications dictionary stores info from FCM messages.  The binary/bundle hash is used
// as a key mapping to values that are themselves dictionaries.  These dictionary values contain the
// name of the binary/bundle and a count of associated binary rules.
@property(nonatomic) NSMutableDictionary *whitelistNotifications;

// whitelistNotificationQueue is used to serialize access to the whitelistNotifications dictionary.
@property(nonatomic) NSOperationQueue *whitelistNotificationQueue;

@property NSUInteger FCMFullSyncInterval;
@property NSUInteger FCMGlobalRuleSyncDeadline;
@property NSUInteger eventBatchSize;

@property MOLFCMClient *FCMClient;

@property(nonatomic) MOLXPCConnection *daemonConn;

@property BOOL targetedRuleSync;

@property(nonatomic) BOOL reachable;

@end

// Called when the network state changes
static void reachabilityHandler(
    SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags, void *info) {
  // Put this check and set on the main thread to ensure serial access.
  dispatch_async(dispatch_get_main_queue(), ^{
    SNTCommandSyncManager *commandSyncManager = (__bridge SNTCommandSyncManager *)info;
    // Only call the setter when there is a change. This will filter out the redundant calls to this
    // callback whenever the network interface states change.
    if (commandSyncManager.reachable != (flags & kSCNetworkReachabilityFlagsReachable)) {
      commandSyncManager.reachable = (flags & kSCNetworkReachabilityFlagsReachable);
    }
  });
}

@implementation SNTCommandSyncManager

#pragma mark init

- (instancetype)initWithDaemonConnection:(MOLXPCConnection *)daemonConn isDaemon:(BOOL)daemon {
  self = [super init];
  if (self) {
    _daemonConn = daemonConn;
    _daemon = daemon;
    _fullSyncTimer = [self createSyncTimerWithBlock:^{
      [self rescheduleTimerQueue:self.fullSyncTimer secondsFromNow:self.FCMFullSyncInterval];
      if (![[SNTConfigurator configurator] syncBaseURL]) return;
      [self lockAction:kFullSync];
      [self preflight];
      [self unlockAction:kFullSync];
    }];
    _ruleSyncTimer = [self createSyncTimerWithBlock:^{
      dispatch_source_set_timer(self.ruleSyncTimer,
                                DISPATCH_TIME_FOREVER, DISPATCH_TIME_FOREVER, 0);
      if (![[SNTConfigurator configurator] syncBaseURL]) return;
      [self lockAction:kRuleSync];
      SNTCommandSyncState *syncState = [self createSyncState];
      syncState.targetedRuleSync = self.targetedRuleSync;
      syncState.whitelistNotifications = self.whitelistNotifications;
      syncState.whitelistNotificationQueue = self.whitelistNotificationQueue;
      SNTCommandSyncRuleDownload *p = [[SNTCommandSyncRuleDownload alloc] initWithState:syncState];
      if ([p sync]) {
        LOGD(@"Rule download complete");
      } else {
        LOGE(@"Rule download failed");
      }
      self.targetedRuleSync = NO;
      [self unlockAction:kRuleSync];
    }];
    _dispatchLock = [[NSCache alloc] init];
    _whitelistNotifications = [NSMutableDictionary dictionary];
    _whitelistNotificationQueue = [[NSOperationQueue alloc] init];
    _whitelistNotificationQueue.maxConcurrentOperationCount = 1;  // make this a serial queue

    _eventBatchSize = kDefaultEventBatchSize;
    _FCMFullSyncInterval = kDefaultFCMFullSyncInterval;
    _FCMGlobalRuleSyncDeadline = kDefaultFCMGlobalRuleSyncDeadline;
  }
  return self;
}

- (void)dealloc {
  // Ensure reachability is always stopped
  [self stopReachability];
}

#pragma mark SNTSyncdXPC protocol methods

- (void)postEventsToSyncServer:(NSArray<SNTStoredEvent *> *)events isFromBundle:(BOOL)isFromBundle {
  SNTCommandSyncState *syncState = [self createSyncState];
  if (isFromBundle) syncState.eventBatchSize = self.eventBatchSize;
  SNTCommandSyncEventUpload *p = [[SNTCommandSyncEventUpload alloc] initWithState:syncState];
  if (events && [p uploadEvents:events]) {
    LOGD(@"Events upload complete");
  } else {
    LOGE(@"Events upload failed.  Will retry again once %@ is reachable",
        [[SNTConfigurator configurator] syncBaseURL].absoluteString);
    [self startReachability];
  }
}

- (void)postBundleEventToSyncServer:(SNTStoredEvent *)event
                              reply:(void (^)(SNTBundleEventAction))reply {
  if (!event) {
    reply(SNTBundleEventActionDropEvents);
    return;
  }
  SNTCommandSyncState *syncState = [self createSyncState];
  SNTCommandSyncEventUpload *p = [[SNTCommandSyncEventUpload alloc] initWithState:syncState];
  if ([p uploadEvents:@[event]]) {
    if ([syncState.bundleBinaryRequests containsObject:event.fileBundleHash]) {
      reply(SNTBundleEventActionSendEvents);
      LOGD(@"Needs related events");
    } else {
      reply(SNTBundleEventActionDropEvents);
      LOGD(@"Bundle event upload complete");
    }
  } else {
    // Related bundle events will be stored and eventually synced, whether the server actually
    // wanted them or not.  If they weren't needed the server will simply ignore them.
    reply(SNTBundleEventActionStoreEvents);
    LOGE(@"Bundle event upload failed.  Will retry again once %@ is reachable",
        [[SNTConfigurator configurator] syncBaseURL].absoluteString);
    [self startReachability];
  }
}

- (void)isFCMListening:(void (^)(BOOL))reply {
  reply(self.FCMClient.isConnected);
}

#pragma mark push notification methods

- (void)listenForPushNotificationsWithSyncState:(SNTCommandSyncState *)syncState {
  if ([self.FCMClient.FCMToken isEqualToString:syncState.FCMToken]) {
    LOGD(@"Continue with the current FCMToken");
    return;
  }

  LOGD(@"Start listening for push notifications");

  WEAKIFY(self);

  [self.FCMClient disconnect];
  NSString *machineID = syncState.machineID;
  self.FCMClient = [[MOLFCMClient alloc] initWithFCMToken:syncState.FCMToken
                                     sessionConfiguration:syncState.session.configuration.copy
                                           messageHandler:^(NSDictionary *message) {
    if (!message || [message isEqual:@{}]) return;
      STRONGIFY(self);
      LOGD(@"%@", message);
      [self.FCMClient acknowledgeMessage:message];
      [self processFCMMessage:message withMachineID:machineID];
  }];

  self.FCMClient.connectionErrorHandler = ^(NSHTTPURLResponse *response, NSError *error) {
    STRONGIFY(self);
    if (response) LOGE(@"FCM fatal response: %@", response);
    if (error) LOGE(@"FCM fatal error: %@", error);
    [self.FCMClient disconnect];
    self.FCMClient = nil;
    [self rescheduleTimerQueue:self.fullSyncTimer secondsFromNow:kDefaultFullSyncInterval];
  };

  self.FCMClient.loggingBlock = ^(NSString *log) {
    LOGD(@"FCMClient: %@", log);
  };

  [self.FCMClient connect];
}

- (void)processFCMMessage:(NSDictionary *)FCMmessage withMachineID:(NSString *)machineID {
  NSDictionary *message = [self messageFromMessageData:[self messageDataFromFCMmessage:FCMmessage]];

  if (!message) {
    LOGD(@"Push notification message is not in the expected format...dropping message");
    return;
  }

  NSString *action = message[kFCMActionKey];
  if (!action) {
    LOGD(@"Push notification message contains no action");
    return;
  }

  // We assume that the incoming FCM message contains name of binary/bundle and a hash.  Rule count
  // info for bundles will be sent out later with the rules themselves.  If the message is related
  // to a bundle, the hash is a bundle hash, otherwise it is just a hash for a single binary.
  // For later use, we store a mapping of bundle/binary hash to a dictionary containing the
  // binary/bundle name so we can send out relevant notifications once the rules are actually
  // downloaded & added to local database.  We use a dictionary value so that we can later add a
  // count field when we start downloading the rules and receive the count information.
  NSString *fileHash = message[kFCMFileHashKey];
  NSString *fileName = message[kFCMFileNameKey];
  if (fileName && fileHash) {
    [self.whitelistNotificationQueue addOperationWithBlock:^{
      self.whitelistNotifications[fileHash] = @{ kFileName : fileName }.mutableCopy;
    }];
  }

  LOGD(@"Push notification action: %@ received", action);

  if ([action isEqualToString:kFullSync]) {
    [self fullSync];
  } else if ([action isEqualToString:kRuleSync]) {
    NSString *targetHostID = message[kFCMTargetHostIDKey];
    if (targetHostID && [targetHostID caseInsensitiveCompare:machineID] == NSOrderedSame) {
      LOGD(@"Targeted rule_sync for host_id: %@", targetHostID);
      self.targetedRuleSync = YES;
      [self ruleSync];
    } else {
      uint32_t delaySeconds = arc4random_uniform((uint32_t)self.FCMGlobalRuleSyncDeadline);
      LOGD(@"Global rule_sync, staggering: %u second delay", delaySeconds);
      [self ruleSyncSecondsFromNow:delaySeconds];
    }
  } else if ([action isEqualToString:kConfigSync]) {
    [self fullSync];
  } else if ([action isEqualToString:kLogSync]) {
    [self fullSync];
  } else {
    LOGD(@"Unrecognised action: %@", action);
  }
}

- (NSData *)messageDataFromFCMmessage:(NSDictionary *)FCMmessage {
  if (![FCMmessage[@"data"] isKindOfClass:[NSDictionary class]]) return nil;
  if (![FCMmessage[@"data"][@"blob"] isKindOfClass:[NSString class]]) return nil;
  return [FCMmessage[@"data"][@"blob"] dataUsingEncoding:NSUTF8StringEncoding];
}

- (NSDictionary *)messageFromMessageData:(NSData *)messageData {
  NSError *error;
  NSDictionary *rawMessage = [NSJSONSerialization JSONObjectWithData:messageData
                                                             options:0
                                                               error:&error];
  if (!rawMessage) {
    LOGD(@"Unable to parse push notification message data: %@", error);
    return nil;
  }

  // Create a new message dropping unexpected values
  NSArray *allowedKeys = @[ kFCMActionKey, kFCMFileHashKey, kFCMFileNameKey, kFCMTargetHostIDKey ];
  NSMutableDictionary *message = [NSMutableDictionary dictionaryWithCapacity:allowedKeys.count];
  for (NSString *key in allowedKeys) {
    if ([rawMessage[key] isKindOfClass:[NSString class]] && [rawMessage[key] length]) {
      message[key] = rawMessage[key];
    }
  }
  return message.count ? [message copy] : nil;
}

#pragma mark sync timer control

- (void)fullSync {
  [self fullSyncSecondsFromNow:0];
}

- (void)fullSyncSecondsFromNow:(uint64_t)seconds {
  if (![self checkLockAction:kFullSync]) {
    LOGD(@"%@ in progress, dropping reschedule request", kFullSync);
    return;
  }
  [self rescheduleTimerQueue:self.fullSyncTimer secondsFromNow:seconds];
}

- (void)ruleSync {
  [self ruleSyncSecondsFromNow:0];
}

- (void)ruleSyncSecondsFromNow:(uint64_t)seconds {
  if (![self checkLockAction:kRuleSync]) {
    LOGD(@"%@ in progress, dropping reschedule request", kRuleSync);
    return;
  }
  [self rescheduleTimerQueue:self.ruleSyncTimer secondsFromNow:seconds];
}

- (void)rescheduleTimerQueue:(dispatch_source_t)timerQueue secondsFromNow:(uint64_t)seconds {
  uint64_t interval = seconds * NSEC_PER_SEC;
  uint64_t leeway = (seconds * 0.5) * NSEC_PER_SEC;
  dispatch_source_set_timer(timerQueue, dispatch_walltime(NULL, interval), interval, leeway);
}

#pragma mark syncing chain

- (void)preflight {
  SNTCommandSyncState *syncState = [self createSyncState];
  SNTCommandSyncPreflight *p = [[SNTCommandSyncPreflight alloc] initWithState:syncState];
  if ([p sync]) {
    LOGD(@"Preflight complete");

    // Clean up reachability if it was started for a non-network error
    [self stopReachability];

    self.eventBatchSize = syncState.eventBatchSize;

    // Start listening for push notifications with a full sync every FCMFullSyncInterval
    if (syncState.daemon && syncState.FCMToken) {
      self.FCMFullSyncInterval = syncState.FCMFullSyncInterval;
      self.FCMGlobalRuleSyncDeadline = syncState.FCMGlobalRuleSyncDeadline;
      [self listenForPushNotificationsWithSyncState:syncState];
    } else if (syncState.daemon) {
      LOGD(@"FCMToken not provided. Sync every %lu min.", kDefaultFullSyncInterval / 60);
      [self.FCMClient disconnect];
      self.FCMClient = nil;
      [self rescheduleTimerQueue:self.fullSyncTimer secondsFromNow:kDefaultFullSyncInterval];
    }

    return [self eventUploadWithSyncState:syncState];
  } else {
    if (!syncState.daemon) {
      LOGE(@"Preflight failed, aborting run");
      exit(1);
    }
    LOGE(@"Preflight failed, will try again once %@ is reachable",
         [[SNTConfigurator configurator] syncBaseURL].absoluteString);
    [self startReachability];
  }
}

- (void)eventUploadWithSyncState:(SNTCommandSyncState *)syncState {
  SNTCommandSyncEventUpload *p = [[SNTCommandSyncEventUpload alloc] initWithState:syncState];
  if ([p sync]) {
    LOGD(@"Event upload complete");
    return [self ruleDownloadWithSyncState:syncState];
  } else {
    LOGE(@"Event upload failed, aborting run");
    if (!syncState.daemon) exit(1);
  }
}

- (void)ruleDownloadWithSyncState:(SNTCommandSyncState *)syncState {
  SNTCommandSyncRuleDownload *p = [[SNTCommandSyncRuleDownload alloc] initWithState:syncState];
  if ([p sync]) {
    LOGD(@"Rule download complete");
    return [self postflightWithSyncState:syncState];
  } else {
    LOGE(@"Rule download failed, aborting run");
    if (!syncState.daemon) exit(1);
  }
}

- (void)postflightWithSyncState:(SNTCommandSyncState *)syncState {
  SNTCommandSyncPostflight *p = [[SNTCommandSyncPostflight alloc] initWithState:syncState];
  if ([p sync]) {
    LOGD(@"Postflight complete");
    LOGI(@"Sync completed successfully");
    if (!syncState.daemon) exit(0);
  } else {
    LOGE(@"Postflight failed");
    if (!syncState.daemon) exit(1);
  }
}

#pragma mark internal helpers

- (dispatch_source_t)createSyncTimerWithBlock:(void (^)(void))block {
  dispatch_source_t timerQueue = dispatch_source_create(
      DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));
  dispatch_source_set_event_handler(timerQueue, block);
  dispatch_resume(timerQueue);
  return timerQueue;
}

- (SNTCommandSyncState *)createSyncState {
  // Gather some data needed during some sync stages
  SNTCommandSyncState *syncState = [[SNTCommandSyncState alloc] init];
  SNTConfigurator *config = [SNTConfigurator configurator];

  syncState.syncBaseURL = config.syncBaseURL;
  if (syncState.syncBaseURL.absoluteString.length == 0) {
    LOGE(@"Missing SyncBaseURL. Can't sync without it.");
    if (!syncState.daemon) exit(1);
  } else if (![syncState.syncBaseURL.scheme isEqual:@"https"]) {
    LOGW(@"SyncBaseURL is not over HTTPS!");
  }

  syncState.machineID = config.machineID;
  if (syncState.machineID.length == 0) {
    LOGE(@"Missing Machine ID. Can't sync without it.");
    if (!syncState.daemon) exit(1);
  }

  syncState.machineOwner = config.machineOwner;
  if (syncState.machineOwner.length == 0) {
    syncState.machineOwner = @"";
    LOGW(@"Missing Machine Owner.");
  }

  dispatch_group_t group = dispatch_group_create();
  dispatch_group_enter(group);
  [[self.daemonConn remoteObjectProxy] xsrfToken:^(NSString *token) {
    syncState.xsrfToken = token;
    dispatch_group_leave(group);
  }];

  MOLAuthenticatingURLSession *authURLSession = [[MOLAuthenticatingURLSession alloc] init];
  authURLSession.userAgent = @"santactl-sync/";
  NSString *santactlVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  if (santactlVersion) {
    authURLSession.userAgent = [authURLSession.userAgent stringByAppendingString:santactlVersion];
  }
  authURLSession.refusesRedirects = YES;
  authURLSession.serverHostname = syncState.syncBaseURL.host;
  authURLSession.loggingBlock = ^(NSString *line) {
    LOGD(@"%@", line);
  };

  // Configure server auth
  if ([config syncServerAuthRootsFile]) {
    authURLSession.serverRootsPemFile = [config syncServerAuthRootsFile];
  } else if ([config syncServerAuthRootsData]) {
    authURLSession.serverRootsPemData = [config syncServerAuthRootsData];
  }

  // Configure client auth
  if ([config syncClientAuthCertificateFile]) {
    authURLSession.clientCertFile = [config syncClientAuthCertificateFile];
    authURLSession.clientCertPassword = [config syncClientAuthCertificatePassword];
  } else if ([config syncClientAuthCertificateCn]) {
    authURLSession.clientCertCommonName = [config syncClientAuthCertificateCn];
  } else if ([config syncClientAuthCertificateIssuer]) {
    authURLSession.clientCertIssuerCn = [config syncClientAuthCertificateIssuer];
  }

  syncState.session = [authURLSession session];
  syncState.daemonConn = self.daemonConn;
  syncState.daemon = self.daemon;

  dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
  return syncState;
}

- (void)lockAction:(NSString *)action {
  [self.dispatchLock setObject:@YES forKey:action];
}

- (void)unlockAction:(NSString *)action {
  [self.dispatchLock removeObjectForKey:action];
}

- (BOOL)checkLockAction:(NSString *)action {
  return ([self.dispatchLock objectForKey:action] == nil);
}

#pragma mark reachability methods

- (void)setReachable:(BOOL)reachable {
  _reachable = reachable;
  if (reachable) {
    [self stopReachability];
    [self fullSync];
  }
}

// Start listening for network state changes on a background thread
- (void)startReachability {
  dispatch_async(dispatch_get_main_queue(), ^{
    if (_reachability) return;
    const char *nodename = [[SNTConfigurator configurator] syncBaseURL].host.UTF8String;
    _reachability = SCNetworkReachabilityCreateWithName(kCFAllocatorDefault, nodename);
    SCNetworkReachabilityContext context = {
      .info = (__bridge_retained void *)self,
      .release = (void (*)(const void *))CFBridgingRelease,
    };
    if (SCNetworkReachabilitySetCallback(_reachability, reachabilityHandler, &context)) {
      SCNetworkReachabilitySetDispatchQueue(_reachability,
          dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));
    } else {
      [self stopReachability];
    }
  });
}

// Stop listening for network state changes
- (void)stopReachability {
  dispatch_async(dispatch_get_main_queue(), ^{
    if (_reachability) {
      SCNetworkReachabilitySetDispatchQueue(_reachability, NULL);
      if (_reachability) CFRelease(_reachability);
      _reachability = NULL;
    }
  });
}

@end
