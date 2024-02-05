/// Copyright 2022 Google Inc. All rights reserved.
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

#import "Source/santasyncservice/SNTSyncService.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTDropRootPrivs.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santasyncservice/SNTSyncBroadcaster.h"
#import "Source/santasyncservice/SNTSyncManager.h"

@interface SNTSyncService ()
@property(nonatomic, readonly) SNTSyncManager *syncManager;
@property(nonatomic, readonly) MOLXPCConnection *daemonConn;
@property(nonatomic, readonly) NSMutableArray *logListeners;
@end

@implementation SNTSyncService

- (instancetype)init {
  self = [super init];
  if (self) {
    _logListeners = [NSMutableArray array];
    MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
    daemonConn.invalidationHandler = ^(void) {
      // Spindown this process if we can't establish a connection
      // or if the daemon is killed or crashes.
      // If we are needed we will be re-launched.
      [self spindown];
    };
    [daemonConn resume];

    // Ensure we have no privileges
    if (!DropRootPrivileges()) {
      LOGE(@"Failed to drop root privileges. Exiting.");
      exit(1);
    }

    // Dropping root privileges to the 'nobody' user causes the default NSURLCache to throw
    // sandbox errors, which are benign but annoying. This line disables the cache entirely.
    [NSURLCache setSharedURLCache:[[NSURLCache alloc] initWithMemoryCapacity:0
                                                                diskCapacity:0
                                                                    diskPath:nil]];

    _daemonConn = daemonConn;
    _syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:daemonConn];

    // This service should only start up if com.google.santa.daemon
    // noticed there is sync server configured and established a connection
    // with us. Go ahead and start syncing!
    [_syncManager syncSecondsFromNow:15];
  }
  return self;
}

- (void)postEventsToSyncServer:(NSArray<SNTStoredEvent *> *)events fromBundle:(BOOL)fromBundle {
  [self.syncManager postEventsToSyncServer:events fromBundle:fromBundle];
}

- (void)postBundleEventToSyncServer:(SNTStoredEvent *)event
                              reply:(void (^)(SNTBundleEventAction))reply {
  [self.syncManager postBundleEventToSyncServer:event reply:reply];
}

- (void)isFCMListening:(void (^)(BOOL))reply {
  [self.syncManager isFCMListening:reply];
}

// TODO(bur): Add support for santactl sync --debug to enable debug logging for that sync.
- (void)syncWithLogListener:(NSXPCListenerEndpoint *)logListener
                   syncType:(SNTSyncType)syncType
                      reply:(void (^)(SNTSyncStatusType))reply {
  MOLXPCConnection *ll = [[MOLXPCConnection alloc] initClientWithListener:logListener];
  ll.remoteInterface =
    [NSXPCInterface interfaceWithProtocol:@protocol(SNTSyncServiceLogReceiverXPC)];
  [ll resume];
  [self.syncManager syncType:syncType
                   withReply:^(SNTSyncStatusType status) {
                     if (status == SNTSyncStatusTypeSyncStarted) {
                       [[SNTSyncBroadcaster broadcaster] addLogListener:ll];
                       return;
                     }
                     [[SNTSyncBroadcaster broadcaster] barrier];
                     [[SNTSyncBroadcaster broadcaster] removeLogListener:ll];
                     reply(status);
                   }];
}

- (void)spindown {
  LOGI(@"Spinning down.");
  exit(0);
}

@end
