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

#import "SNTXPCSyncdInterface.h"

@class SNTXPCConnection;

///
///  Handles push notifications and periodic syncing with a sync server.
///
@interface SNTCommandSyncManager : NSObject<SNTSyncdXPC>

@property(readonly, nonatomic) BOOL daemon;

///
///  Use the designated initializer initWithDaemonConnection:isDaemon:
///
- (instancetype)init NS_UNAVAILABLE;

///
///  Designated initializer.
///
///  @param daemonConn A connection to santad.
///  @param daemon Set to YES if periodic syncing should occur.
///                Set to NO if a single sync should be performed. NO is default.
///
- (instancetype)initWithDaemonConnection:(SNTXPCConnection *)daemonConn
                                isDaemon:(BOOL)daemon NS_DESIGNATED_INITIALIZER;

///
///  Perform a full sync immediately. Non-blocking.
///  If a full sync is already running new requests will be dropped.
///
- (void)fullSync;

///
///  Perform a full sync seconds from now. Non-blocking.
///  If a full sync is already running new requests will be dropped.
///
- (void)fullSyncSecondsFromNow:(uint64_t)seconds;

@end
