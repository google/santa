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

#import <MOLAuthenticatingURLSession.h>

#import "SNTCommandSyncEventUpload.h"
#import "SNTCommandSyncLogUpload.h"
#import "SNTCommandSyncPostflight.h"
#import "SNTCommandSyncPreflight.h"
#import "SNTCommandSyncRuleDownload.h"
#import "SNTCommandSyncState.h"
#import "SNTConfigurator.h"
#import "SNTDropRootPrivs.h"
#import "SNTLogging.h"
#import "SNTStoredEvent.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"
#import "SNTXPCSyncdInterface.h"

@interface SNTCommandSync : NSObject<SNTCommand, SNTSyncdXPC>
@property SNTCommandSyncState *syncState;
@property SNTXPCConnection *listener;
@property dispatch_source_t syncTimer;
@property BOOL isDaemon;
@end

@implementation SNTCommandSync

REGISTER_COMMAND_NAME(@"sync")

#pragma mark SNTCommand protocol methods

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Synchronizes Santa with a configured server.";
}

+ (NSString *)longHelpText {
  return (@"If Santa is configured to synchronize with a a server, "
          @"this is the command used for syncing.\n\n"
          @"Options:\n"
          @"  --clean: Perform a clean sync, erasing all existing rules and requesting a"
          @"           clean sync from the server.");
}

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  // Ensure we have no privileges
  if (!DropRootPrivileges()) {
    LOGE(@"Failed to drop root privileges. Exiting.");
    exit(1);
  }

  SNTConfigurator *config = [SNTConfigurator configurator];
  SNTCommandSync *s = [[self alloc] init];

  // Gather some data needed during some sync stages
  s.syncState = [[SNTCommandSyncState alloc] init];

  s.syncState.syncBaseURL = config.syncBaseURL;
  if (s.syncState.syncBaseURL.absoluteString.length == 0) {
    LOGE(@"Missing SyncBaseURL. Can't sync without it.");
    exit(1);
  } else if (![s.syncState.syncBaseURL.scheme isEqual:@"https"]) {
    LOGW(@"SyncBaseURL is not over HTTPS!");
  }

  s.syncState.machineID = config.machineID;
  if (s.syncState.machineID.length == 0) {
    LOGE(@"Missing Machine ID. Can't sync without it.");
    exit(1);
  }

  s.syncState.machineOwner = config.machineOwner;
  if (s.syncState.machineOwner.length == 0) {
    s.syncState.machineOwner = @"";
    LOGW(@"Missing Machine Owner.");
  }
  
  [daemonConn resume];
  [[daemonConn remoteObjectProxy] xsrfToken:^(NSString *token) {
    s.syncState.xsrfToken = token;
  }];

  // Dropping root privileges to the 'nobody' user causes the default NSURLCache to throw
  // sandbox errors, which are benign but annoying. This line disables the cache entirely.
  [NSURLCache setSharedURLCache:[[NSURLCache alloc] initWithMemoryCapacity:0
                                                              diskCapacity:0
                                                                  diskPath:nil]];


  MOLAuthenticatingURLSession *authURLSession = [[MOLAuthenticatingURLSession alloc] init];
  authURLSession.userAgent = @"santactl-sync/";
  NSString *santactlVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  if (santactlVersion) {
    authURLSession.userAgent = [authURLSession.userAgent stringByAppendingString:santactlVersion];
  }
  authURLSession.refusesRedirects = YES;
  authURLSession.serverHostname = s.syncState.syncBaseURL.host;
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

  s.syncState.session = [authURLSession session];
  s.syncState.daemonConn = daemonConn;
  s.isDaemon = [arguments containsObject:@"--daemon"];

  if (s.isDaemon) {
    [s syncd];
  } else {
    [s preflight];
  }
}

#pragma mark daemon methods

- (void)syncd {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Create listener for return connection from daemon.
  NSXPCListener *listener = [NSXPCListener anonymousListener];
  self.listener = [[SNTXPCConnection alloc] initServerWithListener:listener];
  self.listener.exportedInterface = [SNTXPCSyncdInterface syncdInterface];
  self.listener.exportedObject = self;
  self.listener.acceptedHandler = ^{
    LOGD(@"santad <--> santactl connections established");
    dispatch_semaphore_signal(sema);
  };
  self.listener.invalidationHandler = ^{
    // If santad is unloaded kill santactl
    LOGD(@"exiting");
    exit(0);
  };
  [self.listener resume];

  // Tell daemon to connect back to the above listener.
  [[self.syncState.daemonConn remoteObjectProxy] setSyncdListener:listener.endpoint];

  // Now wait for the connection to come in.
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    [self performSelectorInBackground:@selector(syncd) withObject:nil];
  }

  self.syncTimer = [self createSyncTimer];
  [self rescheduleSyncSecondsFromNow:30];
}

- (dispatch_source_t)createSyncTimer {
  dispatch_source_t syncTimerQ = dispatch_source_create(
      DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));

  dispatch_source_set_event_handler(syncTimerQ, ^{
    [self rescheduleSyncSecondsFromNow:600];

    if (![[SNTConfigurator configurator] syncBaseURL]) return;
    [[SNTConfigurator configurator] setSyncBackOff:NO];
    [self preflight];
  });
  
  dispatch_resume(syncTimerQ);
  
  return syncTimerQ;
}

#pragma mark SNTSyncdXPC protocol methods

- (void)postEventToSyncServer:(SNTStoredEvent *)event {
  SNTCommandSyncEventUpload *p = [[SNTCommandSyncEventUpload alloc] initWithState:self.syncState];
  if (event && [p uploadEvents:@[event]]) {
    LOGD(@"Event upload complete");
  } else {
    LOGE(@"Event upload failed");
  }
}

- (void)rescheduleSyncSecondsFromNow:(uint64_t)seconds {
  uint64_t interval = seconds * NSEC_PER_SEC;
  uint64_t leeway = (seconds * 0.05) * NSEC_PER_SEC;
  dispatch_source_set_timer(self.syncTimer, dispatch_walltime(NULL, interval), interval, leeway);
}

#pragma mark sync methods

- (void)preflight {
  SNTCommandSyncPreflight *p = [[SNTCommandSyncPreflight alloc] initWithState:self.syncState];
  if ([p sync]) {
    LOGD(@"Preflight complete");
    if (self.syncState.uploadLogURL) {
      return [self logUpload];
    } else {
      return [self eventUpload];
    }
  } else {
    LOGE(@"Preflight failed, aborting run");
    if (!self.isDaemon) exit(1);
  }
}

- (void)logUpload {
  SNTCommandSyncLogUpload *p = [[SNTCommandSyncLogUpload alloc] initWithState:self.syncState];
  if ([p sync]) {
    LOGD(@"Log upload complete");
  } else {
    LOGE(@"Log upload failed, continuing anyway");
  }
  return [self eventUpload];
}

- (void)eventUpload {
  SNTCommandSyncEventUpload *p = [[SNTCommandSyncEventUpload alloc] initWithState:self.syncState];
  if ([p sync]) {
    LOGD(@"Event upload complete");
    return [self ruleDownload];
  } else {
    LOGE(@"Event upload failed, aborting run");
    if (!self.isDaemon) exit(1);
  }
}

- (void)ruleDownload {
  SNTCommandSyncRuleDownload *p = [[SNTCommandSyncRuleDownload alloc] initWithState:self.syncState];
  if ([p sync]) {
    LOGD(@"Rule download complete");
    if (self.syncState.bundleBinaryRequests.count) {
      return [self eventUploadBundleBinaries];
    }
    return [self postflight];
  } else {
    LOGE(@"Rule download failed, aborting run");
    if (!self.isDaemon) exit(1);
  }
}

- (void)eventUploadBundleBinaries {
  SNTCommandSyncEventUpload *p = [[SNTCommandSyncEventUpload alloc] initWithState:self.syncState];
  if ([p syncBundleEvents]) {
    LOGD(@"Event upload for bundle binaries complete");
  } else {
    LOGW(@"Event upload for bundle binary search failed");
  }
  return [self postflight];
}

- (void)postflight {
  SNTCommandSyncPostflight *p = [[SNTCommandSyncPostflight alloc] initWithState:self.syncState];
  if ([p sync]) {
    LOGD(@"Postflight complete");
    LOGI(@"Sync completed successfully");
    if (!self.isDaemon) exit(0);
  } else {
    LOGE(@"Postflight failed");
    if (!self.isDaemon) exit(1);
  }
}

@end
