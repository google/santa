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

#import "SNTCommonEnums.h"
#import "SNTKernelCommon.h"

@class SNTRule;
@class SNTStoredEvent;
@class SNTXPCConnection;

///
///  Protocol implemented by santad and utilized by santactl
///
@protocol SNTDaemonControlXPC

///
///  Kernel ops
///
- (void)cacheCount:(void (^)(int64_t))reply;
- (void)flushCache:(void (^)(BOOL))reply;
- (void)checkCacheForVnodeID:(u_int64_t)vnodeID withReply:(void (^)(santa_action_t))reply;

///
///  Database ops
///
- (void)databaseRuleCounts:(void (^)(int64_t binary, int64_t certificate))reply;
- (void)databaseRuleAddRules:(NSArray *)rules
                  cleanSlate:(BOOL)cleanSlate
                       reply:(void (^)(NSError *error))reply;

- (void)databaseEventCount:(void (^)(int64_t count))reply;
- (void)databaseEventForSHA256:(NSString *)sha256 reply:(void (^)(SNTStoredEvent *))reply;
- (void)databaseEventsPending:(void (^)(NSArray *events))reply;
- (void)databaseRemoveEventsWithIDs:(NSArray *)ids;
- (void)databaseBinaryRuleForSHA256:(NSString *)sha256 reply:(void (^)(SNTRule *))reply;
- (void)databaseCertificateRuleForSHA256:(NSString *)sha256 reply:(void (^)(SNTRule *))reply;

///
///  Config ops
///
- (void)watchdogInfo:(void (^)(uint64_t, uint64_t, double, double))reply;
- (void)clientMode:(void (^)(SNTClientMode))reply;
- (void)setClientMode:(SNTClientMode)mode reply:(void (^)())reply;
- (void)xsrfToken:(void (^)(NSString *))reply;
- (void)setXsrfToken:(NSString *)token reply:(void (^)())reply;
- (void)setNextSyncInterval:(uint64_t)seconds reply:(void (^)())reply;
- (void)setSyncLastSuccess:(NSDate *)date reply:(void (^)())reply;
- (void)setSyncCleanRequired:(BOOL)cleanReqd reply:(void (^)())reply;
- (void)setWhitelistPathRegex:(NSString *)pattern reply:(void (^)())reply;
- (void)setBlacklistPathRegex:(NSString *)pattern reply:(void (^)())reply;

///
///  GUI Ops
///
- (void)setNotificationListener:(NSXPCListenerEndpoint *)listener;

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

///
///  Retrieve a pre-configured SNTXPCConnection for communicating with santad.
///  Connections just needs any handlers set and then can be resumed and used.
///
+ (SNTXPCConnection *)configuredConnection;

@end
