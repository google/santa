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

#include "SNTCommonEnums.h"

@class SNTRule;
@class SNTStoredEvent;

///
///  Protocol implemented by santad and utilized by santactl
///
@protocol SNTDaemonControlXPC

///
///  Kernel ops
///
- (void)cacheCount:(void (^)(int64_t))reply;
- (void)flushCache:(void (^)(BOOL))reply;

///
///  Database ops
///
- (void)databaseRuleCounts:(void (^)(int64_t binary, int64_t certificate))reply;
- (void)databaseRuleAddRule:(SNTRule *)rule cleanSlate:(BOOL)cleanSlate reply:(void (^)())reply;
- (void)databaseRuleAddRules:(NSArray *)rules cleanSlate:(BOOL)cleanSlate reply:(void (^)())reply;

- (void)databaseEventCount:(void (^)(int64_t count))reply;
- (void)databaseEventForSHA256:(NSString *)sha256 reply:(void (^)(SNTStoredEvent *))reply;
- (void)databaseEventsPending:(void (^)(NSArray *events))reply;
- (void)databaseRemoveEventsWithIDs:(NSArray *)ids;

///
///  Misc ops
///
- (void)clientMode:(void (^)(santa_clientmode_t))reply;
- (void)setClientMode:(santa_clientmode_t)mode reply:(void (^)())reply;

@end

@interface SNTXPCControlInterface : NSObject

///
///  Returns the MachService ID for this service.
///
+ (NSString *)serviceId;

///
///  Returns an initialized NSXPCInterface for the SNTDaemonControlXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning
///
+ (NSXPCInterface *)controlInterface;

@end
