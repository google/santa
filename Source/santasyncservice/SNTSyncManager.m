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

#import "Source/santasyncservice/SNTSyncManager.h"

#import <MOLAuthenticatingURLSession/MOLAuthenticatingURLSession.h>
#import <MOLXPCConnection/MOLXPCConnection.h>
#import <SystemConfiguration/SystemConfiguration.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santasyncservice/SNTPushNotifications.h"
#import "Source/santasyncservice/SNTSyncEventUpload.h"
#import "Source/santasyncservice/SNTSyncLogging.h"
#import "Source/santasyncservice/SNTSyncPostflight.h"
#import "Source/santasyncservice/SNTSyncPreflight.h"
#import "Source/santasyncservice/SNTSyncRuleDownload.h"
#import "Source/santasyncservice/SNTSyncState.h"

static const uint8_t kMaxEnqueuedSyncs = 2;

@interface SNTSyncManager () <SNTPushNotificationsDelegate> {
  SCNetworkReachabilityRef _reachability;
}

@property(nonatomic) dispatch_source_t fullSyncTimer;
@property(nonatomic) dispatch_source_t ruleSyncTimer;

@property(nonatomic, readonly) dispatch_queue_t syncQueue;
@property(nonatomic, readonly) dispatch_semaphore_t syncLimiter;

@property(nonatomic) MOLXPCConnection *daemonConn;

@property(nonatomic) BOOL reachable;

@property SNTPushNotifications *pushNotifications;

@property NSUInteger eventBatchSize;

@property NSString *xsrfToken;
@property NSString *xsrfTokenHeader;

@end

// Called when the network state changes
static void reachabilityHandler(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags,
                                void *info) {
  // Put this check and set on the main thread to ensure serial access.
  dispatch_async(dispatch_get_main_queue(), ^{
    SNTSyncManager *commandSyncManager = (__bridge SNTSyncManager *)info;
    // Only call the setter when there is a change. This will filter out the redundant calls to this
    // callback whenever the network interface states change.
    int reachable =
      (flags & kSCNetworkReachabilityFlagsReachable) == kSCNetworkReachabilityFlagsReachable;
    if (commandSyncManager.reachable != reachable) {
      commandSyncManager.reachable = reachable;
    }
  });
}

@implementation SNTSyncManager

#pragma mark init

- (instancetype)initWithDaemonConnection:(MOLXPCConnection *)daemonConn {
  self = [super init];
  if (self) {
    _daemonConn = daemonConn;
    _pushNotifications = [[SNTPushNotifications alloc] init];
    _pushNotifications.delegate = self;
    _fullSyncTimer = [self createSyncTimerWithBlock:^{
      [self rescheduleTimerQueue:self.fullSyncTimer
                  secondsFromNow:_pushNotifications.pushNotificationsFullSyncInterval];
      [self syncAndMakeItClean:NO withReply:NULL];
    }];
    _ruleSyncTimer = [self createSyncTimerWithBlock:^{
      dispatch_source_set_timer(self.ruleSyncTimer, DISPATCH_TIME_FOREVER, DISPATCH_TIME_FOREVER,
                                0);
      [self ruleSyncImpl];
    }];
    _syncQueue = dispatch_queue_create("com.google.santa.syncservice", DISPATCH_QUEUE_SERIAL);
    _syncLimiter = dispatch_semaphore_create(kMaxEnqueuedSyncs);

    _eventBatchSize = kDefaultEventBatchSize;
  }
  return self;
}

- (void)dealloc {
  // Ensure reachability is always stopped
  [self stopReachability];
}

#pragma mark SNTSyncServiceXPC methods

- (void)postEventsToSyncServer:(NSArray<SNTStoredEvent *> *)events fromBundle:(BOOL)isFromBundle {
  SNTSyncStatusType status = SNTSyncStatusTypeUnknown;
  SNTSyncState *syncState = [self createSyncStateWithStatus:&status];
  if (!syncState) {
    LOGE(@"Events upload failed to create sync state: %ld", status);
    return;
  }
  if (isFromBundle) syncState.eventBatchSize = self.eventBatchSize;
  SNTSyncEventUpload *p = [[SNTSyncEventUpload alloc] initWithState:syncState];
  if (events && [p uploadEvents:events]) {
    LOGD(@"Events upload complete");
  } else {
    LOGE(@"Events upload failed.  Will retry again once %@ is reachable",
         [[SNTConfigurator configurator] syncBaseURL].absoluteString);
    [self startReachability];
  }
  self.xsrfToken = syncState.xsrfToken;
  self.xsrfTokenHeader = syncState.xsrfTokenHeader;
}

- (void)postBundleEventToSyncServer:(SNTStoredEvent *)event
                              reply:(void (^)(SNTBundleEventAction))reply {
  if (!event) {
    reply(SNTBundleEventActionDropEvents);
    return;
  }
  SNTSyncStatusType status = SNTSyncStatusTypeUnknown;
  SNTSyncState *syncState = [self createSyncStateWithStatus:&status];
  if (!syncState) {
    LOGE(@"Bundle event upload failed to create sync state: %ld", status);
    reply(SNTBundleEventActionDropEvents);
    return;
  }
  SNTSyncEventUpload *p = [[SNTSyncEventUpload alloc] initWithState:syncState];
  if ([p uploadEvents:@[ event ]]) {
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
  self.xsrfToken = syncState.xsrfToken;
  self.xsrfTokenHeader = syncState.xsrfTokenHeader;
}

- (void)isFCMListening:(void (^)(BOOL))reply {
  reply(self.pushNotifications.isConnected);
}

#pragma mark sync control / SNTPushNotificationsDelegate methods

- (void)sync {
  [self syncSecondsFromNow:0];
}

- (void)syncSecondsFromNow:(uint64_t)seconds {
  [self rescheduleTimerQueue:self.fullSyncTimer secondsFromNow:seconds];
}

- (void)syncAndMakeItClean:(BOOL)clean withReply:(void (^)(SNTSyncStatusType))reply {
  if (dispatch_semaphore_wait(self.syncLimiter, DISPATCH_TIME_NOW)) {
    if (reply) reply(SNTSyncStatusTypeTooManySyncsInProgress);
    return;
  }
  dispatch_async(self.syncQueue, ^() {
    SLOGI(@"Starting sync...");
    if (clean) {
      dispatch_semaphore_t sema = dispatch_semaphore_create(0);
      [[self.daemonConn remoteObjectProxy] setSyncCleanRequired:YES
                                                          reply:^() {
                                                            dispatch_semaphore_signal(sema);
                                                          }];
      if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC))) {
        SLOGE(@"Timeout waiting for daemon");
        if (reply) reply(SNTSyncStatusTypeDaemonTimeout);
        return;
      }
    }
    if (reply) reply(SNTSyncStatusTypeSyncStarted);
    SNTSyncStatusType status = [self preflight];
    if (reply) reply(status);
    dispatch_semaphore_signal(self.syncLimiter);
  });
}

- (void)ruleSync {
  [self ruleSyncSecondsFromNow:0];
}

- (void)ruleSyncSecondsFromNow:(uint64_t)seconds {
  [self rescheduleTimerQueue:self.ruleSyncTimer secondsFromNow:seconds];
}

- (void)rescheduleTimerQueue:(dispatch_source_t)timerQueue secondsFromNow:(uint64_t)seconds {
  uint64_t interval = seconds * NSEC_PER_SEC;
  uint64_t leeway = (seconds * 0.5) * NSEC_PER_SEC;
  dispatch_source_set_timer(timerQueue, dispatch_walltime(NULL, interval), interval, leeway);
}
- (void)ruleSyncImpl {
  // Rule only syncs are exclusivly scheduled by self.ruleSyncTimer. We do not need to worry about
  // using self.syncLimiter here. However we do want to do the work on self.syncQueue so we do not
  // overlap with a full sync.
  dispatch_async(self.syncQueue, ^() {
    if (![[SNTConfigurator configurator] syncBaseURL]) return;
    SNTSyncStatusType status = SNTSyncStatusTypeUnknown;
    SNTSyncState *syncState = [self createSyncStateWithStatus:&status];
    if (!syncState) {
      LOGE(@"Rule sync failed to create sync state: %ld", status);
      return;
    }
    SNTSyncRuleDownload *p = [[SNTSyncRuleDownload alloc] initWithState:syncState];
    BOOL ret = [p sync];
    LOGD(@"Rule download %@", ret ? @"complete" : @"failed");
    self.xsrfToken = syncState.xsrfToken;
    self.xsrfTokenHeader = syncState.xsrfTokenHeader;
  });
}

- (void)preflightSync {
  [self preflightOnly:YES];
}

#pragma mark syncing chain

- (SNTSyncStatusType)preflight {
  return [self preflightOnly:NO];
}

- (SNTSyncStatusType)preflightOnly:(BOOL)preflightOnly {
  SNTSyncStatusType status = SNTSyncStatusTypeUnknown;
  SNTSyncState *syncState = [self createSyncStateWithStatus:&status];
  if (!syncState) {
    return status;
  }

  SLOGD(@"Preflight starting");
  SNTSyncPreflight *p = [[SNTSyncPreflight alloc] initWithState:syncState];
  if ([p sync]) {
    SLOGD(@"Preflight complete");
    self.xsrfToken = syncState.xsrfToken;
    self.xsrfTokenHeader = syncState.xsrfTokenHeader;

    // Clean up reachability if it was started for a non-network error
    [self stopReachability];

    self.eventBatchSize = syncState.eventBatchSize;

    // Start listening for push notifications with a full sync every
    // pushNotificationsFullSyncInterval.
    if ([SNTConfigurator configurator].fcmEnabled) {
      [self.pushNotifications listenWithSyncState:syncState];
    } else {
      LOGD(@"Push notifications are not enabled. Sync every %lu min.",
           syncState.fullSyncInterval / 60);
      [self rescheduleTimerQueue:self.fullSyncTimer secondsFromNow:syncState.fullSyncInterval];
    }

    if (preflightOnly) return SNTSyncStatusTypeSuccess;
    return [self eventUploadWithSyncState:syncState];
  }

  LOGE(@"Preflight failed, will try again once %@ is reachable",
       [[SNTConfigurator configurator] syncBaseURL].absoluteString);
  [self startReachability];
  return SNTSyncStatusTypePreflightFailed;
}

- (SNTSyncStatusType)eventUploadWithSyncState:(SNTSyncState *)syncState {
  SLOGD(@"Event upload starting");
  SNTSyncEventUpload *p = [[SNTSyncEventUpload alloc] initWithState:syncState];
  if ([p sync]) {
    SLOGD(@"Event upload complete");
    return [self ruleDownloadWithSyncState:syncState];
  }

  SLOGE(@"Event upload failed, aborting run");
  return SNTSyncStatusTypeEventUploadFailed;
}

- (SNTSyncStatusType)ruleDownloadWithSyncState:(SNTSyncState *)syncState {
  SLOGD(@"Rule download starting");
  SNTSyncRuleDownload *p = [[SNTSyncRuleDownload alloc] initWithState:syncState];
  if ([p sync]) {
    SLOGD(@"Rule download complete");
    return [self postflightWithSyncState:syncState];
  }

  SLOGE(@"Rule download failed, aborting run");
  return SNTSyncStatusTypeRuleDownloadFailed;
}

- (SNTSyncStatusType)postflightWithSyncState:(SNTSyncState *)syncState {
  SLOGD(@"Postflight starting");
  SNTSyncPostflight *p = [[SNTSyncPostflight alloc] initWithState:syncState];
  if ([p sync]) {
    SLOGD(@"Postflight complete");
    SLOGI(@"Sync completed successfully");
    return SNTSyncStatusTypeSuccess;
  }
  SLOGE(@"Postflight failed");
  return SNTSyncStatusTypePostflightFailed;
}

#pragma mark internal helpers

- (dispatch_source_t)createSyncTimerWithBlock:(void (^)(void))block {
  dispatch_source_t timerQueue =
    dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                           dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));
  dispatch_source_set_event_handler(timerQueue, block);
  dispatch_resume(timerQueue);
  return timerQueue;
}

- (SNTSyncState *)createSyncStateWithStatus:(SNTSyncStatusType *)status {
  // Gather some data needed during some sync stages
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  SNTConfigurator *config = [SNTConfigurator configurator];

  syncState.syncBaseURL = config.syncBaseURL;
  if (syncState.syncBaseURL.absoluteString.length == 0) {
    SLOGE(@"Missing SyncBaseURL. Can't sync without it.");
    if (*status) *status = SNTSyncStatusTypeMissingSyncBaseURL;
    return nil;
  } else if (![syncState.syncBaseURL.scheme isEqual:@"https"]) {
    SLOGW(@"SyncBaseURL is not over HTTPS!");
  }

  syncState.machineID = config.machineID;
  if (syncState.machineID.length == 0) {
    SLOGE(@"Missing Machine ID. Can't sync without it.");
    if (*status) *status = SNTSyncStatusTypeMissingMachineID;
    return nil;
  }

  syncState.machineOwner = config.machineOwner;
  if (syncState.machineOwner.length == 0) {
    syncState.machineOwner = @"";
    SLOGW(@"Missing Machine Owner.");
  }

  syncState.xsrfToken = self.xsrfToken;
  syncState.xsrfTokenHeader = self.xsrfTokenHeader;

  NSURLSessionConfiguration *sessConfig = [NSURLSessionConfiguration defaultSessionConfiguration];
  sessConfig.connectionProxyDictionary = [[SNTConfigurator configurator] syncProxyConfig];

  MOLAuthenticatingURLSession *authURLSession =
    [[MOLAuthenticatingURLSession alloc] initWithSessionConfiguration:sessConfig];
  authURLSession.userAgent = @"santactl-sync/";
  NSString *santactlVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  if (santactlVersion) {
    authURLSession.userAgent = [authURLSession.userAgent stringByAppendingString:santactlVersion];
  }
  authURLSession.refusesRedirects = YES;
  authURLSession.serverHostname = syncState.syncBaseURL.host;
  authURLSession.loggingBlock = ^(NSString *line) {
    SLOGD(@"%@", line);
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
  syncState.contentEncoding = config.syncClientContentEncoding;
  syncState.pushNotificationsToken = self.pushNotifications.token;

  return syncState;
}

#pragma mark reachability methods

- (void)setReachable:(BOOL)reachable {
  _reachable = reachable;
  if (reachable) {
    [self stopReachability];
    [self sync];
  }
}

// Start listening for network state changes on a background thread
- (void)startReachability {
  dispatch_async(dispatch_get_main_queue(), ^{
    if (self->_reachability) return;
    const char *nodename = [[SNTConfigurator configurator] syncBaseURL].host.UTF8String;
    self->_reachability = SCNetworkReachabilityCreateWithName(kCFAllocatorDefault, nodename);
    SCNetworkReachabilityContext context = {
      .info = (__bridge_retained void *)self,
      .release = (void (*)(const void *))CFBridgingRelease,
    };
    if (SCNetworkReachabilitySetCallback(self->_reachability, reachabilityHandler, &context)) {
      SCNetworkReachabilitySetDispatchQueue(
        self->_reachability, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));
    } else {
      [self stopReachability];
    }
  });
}

// Stop listening for network state changes
- (void)stopReachability {
  dispatch_async(dispatch_get_main_queue(), ^{
    if (self->_reachability) {
      SCNetworkReachabilitySetDispatchQueue(self->_reachability, NULL);
      if (self->_reachability) CFRelease(self->_reachability);
      self->_reachability = NULL;
    }
  });
}

@end
