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

@import SystemConfiguration;

#import <MOLAuthenticatingURLSession.h>
#import <MOLFCMClient/MOLFCMClient.h>

#import "SNTConfigurator.h"
#import "SNTCommandSyncConstants.h"
#import "SNTCommandSyncEventUpload.h"
#import "SNTCommandSyncLogUpload.h"
#import "SNTCommandSyncPostflight.h"
#import "SNTCommandSyncPreflight.h"
#import "SNTCommandSyncRuleDownload.h"
#import "SNTCommandSyncState.h"
#import "SNTLogging.h"
#import "SNTStrengthify.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"
#import "SNTXPCSyncdInterface.h"

// Syncing time constant
const uint64_t kFullSyncInterval = 600;

@interface SNTCommandSyncManager () {
  SCNetworkReachabilityRef _reachability;
}
@property(nonatomic) dispatch_source_t fullSyncTimer;
@property(nonatomic) dispatch_source_t ruleSyncTimer;
@property(nonatomic) NSCache *dispatchLock;
@property(nonatomic) NSCache *ruleSyncCache;
@property MOLFCMClient *FCMClient;
@property(nonatomic) SNTXPCConnection *daemonConn;
@property BOOL targetedRuleSync;
@property(nonatomic) BOOL reachable;
@end

// Called when the network state changes
static void reachabilityHandler(
    SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags, void *info) {
  // Ensure state changes are processed in order.
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

- (instancetype)initWithDaemonConnection:(SNTXPCConnection *)daemonConn isDaemon:(BOOL)daemon {
  self = [super init];
  if (self) {
    _daemonConn = daemonConn;
    _daemon = daemon;
    _fullSyncTimer = [self createSyncTimerWithBlock:^{
      [self rescheduleTimerQueue:self.fullSyncTimer
                  secondsFromNow:[SNTConfigurator configurator].FCMFullSyncInterval];
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
      syncState.ruleSyncCache = self.ruleSyncCache;
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
    _ruleSyncCache = [[NSCache alloc] init];
  }
  return self;
}

#pragma mark SNTSyncdXPC protocol methods

- (void)postEventToSyncServer:(SNTStoredEvent *)event {
  SNTCommandSyncEventUpload *p = [[SNTCommandSyncEventUpload alloc]
                                     initWithState:[self createSyncState]];
  if (event && [p uploadEvents:@[event]]) {
    LOGD(@"Event upload complete");
  } else {
    LOGE(@"Event upload failed");
  }
}

- (void)rescheduleSyncSecondsFromNow:(uint64_t)seconds {
  [self rescheduleTimerQueue:self.fullSyncTimer secondsFromNow:seconds];
}

- (void)isFCMListening:(void (^)(BOOL))reply {
  reply((self.FCMClient.FCMToken != nil));
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

  self.FCMClient.connectionErrorHandler = ^(NSError *error) {
    STRONGIFY(self);
    LOGE(@"FCM connection error: %@", error);
    [self.FCMClient disconnect];
    self.FCMClient = nil;
    [self rescheduleTimerQueue:self.fullSyncTimer secondsFromNow:kFullSyncInterval];
  };
  
  self.FCMClient.loggingBlock = ^(NSString *log) {
    LOGD(@"%@", log);
  };
  
  [self.FCMClient connect];
}

- (void)processFCMMessage:(NSDictionary *)FCMmessage withMachineID:(NSString *)machineID {
  NSData *entryData;

  // Sort through the entries in the FCM message.
  for (NSDictionary *entry in FCMmessage[@"data"]) {
    if ([entry[@"key"] isEqualToString:@"blob"]) {
      entryData = [entry[@"value"] dataUsingEncoding:NSUTF8StringEncoding];
      break;
    }
  }

  if (!entryData) {
    LOGD(@"Push notification message is not in the expected format...dropping message");
    return;
  }

  NSError *error;
  NSDictionary *actionMessage = [NSJSONSerialization JSONObjectWithData:entryData
                                                                options:NSJSONReadingAllowFragments
                                                                  error:&error];
  if (!actionMessage) {
    LOGD(@"Unable to parse push notification message value: %@", error);
    return;
  }

  // Store the file name and hash in a cache. When the rule is actually added, use the cache
  // to build a user notification.
  NSString *fileHash = actionMessage[@"file_hash"];
  NSString *fileName = actionMessage[@"file_name"];
  if (fileName && fileHash) {
    [self.ruleSyncCache setObject:fileName forKey:fileHash];
  }

  NSString *action = actionMessage[@"action"];
  if (action) {
    LOGD(@"Push notification action: %@ received", action);
  } else {
    LOGD(@"Push notification message contains no action");
  }

  if ([action isEqualToString:kFullSync]) {
    [self fullSync];
  } else if ([action isEqualToString:kRuleSync]) {
    NSString *targetMachineID = actionMessage[@"target_host_id"];
    if (![targetMachineID isKindOfClass:[NSNull class]] &&
        [targetMachineID.lowercaseString isEqualToString:machineID.lowercaseString]) {
      self.targetedRuleSync = YES;
      [self ruleSync];
    } else {
      uint32_t delaySeconds =
          arc4random_uniform((u_int32_t)[SNTConfigurator configurator].FCMGlobalRuleLeeway);
      LOGD(@"Staggering rule download, %u second delay for this machine", delaySeconds);
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

    // Start listening for push notifications with a full sync every kFullSyncFCMInterval or
    // revert to full syncing every kFullSyncInterval.
    if (syncState.daemon && syncState.FCMToken) {
      [self listenForPushNotificationsWithSyncState:syncState];
    } else if (syncState.daemon) {
      LOGD(@"FCMToken not provided. Sync every %llu min.", kFullSyncInterval / 60);
      [self.FCMClient disconnect];
      self.FCMClient = nil;
      [self rescheduleTimerQueue:self.fullSyncTimer secondsFromNow:kFullSyncInterval];
    }

    if (syncState.uploadLogURL) {
      return [self logUploadWithSyncState:syncState];
    } else {
      return [self eventUploadWithSyncState:syncState];
    }
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

- (void)logUploadWithSyncState:(SNTCommandSyncState *)syncState {
  SNTCommandSyncLogUpload *p = [[SNTCommandSyncLogUpload alloc] initWithState:syncState];
  if ([p sync]) {
    LOGD(@"Log upload complete");
  } else {
    LOGE(@"Log upload failed, continuing anyway");
  }
  return [self eventUploadWithSyncState:syncState];
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

- (dispatch_source_t)createSyncTimerWithBlock:(void (^)())block {
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

  [[self.daemonConn remoteObjectProxy] xsrfToken:^(NSString *token) {
    syncState.xsrfToken = token;
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
  if (_reachability) return;
  const char *nodename = [[SNTConfigurator configurator] syncBaseURL].host.UTF8String;
  _reachability = SCNetworkReachabilityCreateWithName(kCFAllocatorDefault, nodename);
  SCNetworkReachabilityContext context = {
    .info = (__bridge void *)self
  };
  if (SCNetworkReachabilitySetCallback(_reachability, reachabilityHandler, &context)) {
    SCNetworkReachabilitySetDispatchQueue(
        _reachability, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));
  } else {
    [self stopReachability];
  }
}

// Stop listening for network state changes
- (void)stopReachability {
  if (_reachability) {
    SCNetworkReachabilitySetDispatchQueue(_reachability, NULL);
    if (_reachability) CFRelease(_reachability);
    _reachability = NULL;
  }
}

@end
