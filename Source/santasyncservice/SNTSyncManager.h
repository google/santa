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

#import <Foundation/Foundation.h>

#import "Source/common/SNTXPCSyncServiceInterface.h"

@class MOLXPCConnection;

///
///  Handles push notifications and periodic syncing with a sync server.
///
@interface SNTSyncManager : NSObject

///
///  Use the designated initializer initWithDaemonConnection:isDaemon:
///
- (instancetype)init NS_UNAVAILABLE;

///
///  Designated initializer.
///
///  @param daemonConn A connection to santad.
///
- (instancetype)initWithDaemonConnection:(MOLXPCConnection *)daemonConn NS_DESIGNATED_INITIALIZER;

///
///  Perform a sync immediately. Non-blocking.
///  If a sync is already running new requests will be dropped.
///
- (void)sync;

///
///  Perform a sync seconds from now. Non-blocking.
///  If a sync is already running new requests will be dropped.
///
- (void)syncSecondsFromNow:(uint64_t)seconds;

///
///  Perform an out of band sync.
///
///  Syncs are enqueued in order and executed serially. kMaxEnqueuedSyncs limits the number of syncs
///  in the queue. If the queue is full calls to this method will be dropped and
///  SNTSyncStatusTypeTooManySyncsInProgress will be passed into the reply block.
///
///  The SNTSyncStatusTypeSyncStarted will be passed into the reply block when the sync starts. The
///  reply block will be called again with a SNTSyncStatusType when the sync has completed or
///  failed.
///
///  Pass true to isClean to perform a clean sync, defaults to false.
///
- (void)syncAndMakeItClean:(BOOL)clean withReply:(void (^)(SNTSyncStatusType))reply;

///
///  Handle SNTSyncServiceXPC messages forwarded from SNTSyncService.
///
- (void)postEventsToSyncServer:(NSArray<SNTStoredEvent *> *)events fromBundle:(BOOL)isFromBundle;
- (void)postBundleEventToSyncServer:(SNTStoredEvent *)event
                              reply:(void (^)(SNTBundleEventAction))reply;
- (void)isFCMListening:(void (^)(BOOL))reply;

@end
