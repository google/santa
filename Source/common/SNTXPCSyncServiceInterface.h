/// Copyright 2020 Google Inc. All rights reserved.
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

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTCommonEnums.h"

@class SNTStoredEvent;

///  A block that reports the number of rules processed.
///  TODO(bur): Add more details about the sync.
typedef void (^SNTFullSyncReplyBlock)(NSNumber *rulesProcessed);

///  Protocol implemented by syncservice and utilized by daemon and ctl for communication with a sync server.
@protocol SNTSyncServiceXPC
- (void)postEventsToSyncServer:(NSArray<SNTStoredEvent *> *)events fromBundle:(BOOL)fromBundle;
- (void)postBundleEventToSyncServer:(SNTStoredEvent *)event
                              reply:(void (^)(SNTBundleEventAction))reply;
- (void)isFCMListening:(void (^)(BOOL))reply;
- (void)performFullSyncWithReply:(SNTFullSyncReplyBlock)reply;
@end

@interface SNTXPCSyncServiceInterface : NSObject

///
///  Returns an initialized NSXPCInterface for the SNTSyncServiceXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning.
///
+ (NSXPCInterface *)syncServiceInterface;

///
///  Returns the MachService ID for this service.
///
+ (NSString *)serviceID;

///
///  Retrieve a pre-configured MOLXPCConnection for communicating with syncservice.
///  Connections just needs any handlers set and then can be resumed and used.
///
+ (MOLXPCConnection *)configuredConnection;

@end

