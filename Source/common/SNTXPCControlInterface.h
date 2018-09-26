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

#import "SNTXPCUnprivilegedControlInterface.h"

///
///  Protocol implemented by santad and utilized by santactl (privileged operations)
///
@protocol SNTDaemonControlXPC <SNTUnprivilegedDaemonControlXPC>

///
///  Kernel ops
///
- (void)flushCache:(void (^)(BOOL))reply;

///
///  Database ops
///
- (void)databaseRuleAddRules:(NSArray *)rules
                  cleanSlate:(BOOL)cleanSlate
                       reply:(void (^)(NSError *error))reply;
- (void)databaseEventsPending:(void (^)(NSArray *events))reply;
- (void)databaseRemoveEventsWithIDs:(NSArray *)ids;
- (void)databaseRuleForBinarySHA256:(NSString *)binarySHA256
                  certificateSHA256:(NSString *)certificateSHA256
                              reply:(void (^)(SNTRule *))reply;

///
///  Config ops
///
- (void)setClientMode:(SNTClientMode)mode reply:(void (^)(void))reply;
- (void)setXsrfToken:(NSString *)token reply:(void (^)(void))reply;
- (void)setFullSyncLastSuccess:(NSDate *)date reply:(void (^)(void))reply;
- (void)setRuleSyncLastSuccess:(NSDate *)date reply:(void (^)(void))reply;
- (void)setSyncCleanRequired:(BOOL)cleanReqd reply:(void (^)(void))reply;
- (void)setWhitelistPathRegex:(NSString *)pattern reply:(void (^)(void))reply;
- (void)setBlacklistPathRegex:(NSString *)pattern reply:(void (^)(void))reply;
- (void)setEnableBundles:(BOOL)bundlesEnabled reply:(void (^)(void))reply;
- (void)setEnableTransitiveWhitelisting:(BOOL)enabled reply:(void (^)(void))reply;

///
///  Syncd Ops
///
- (void)setSyncdListener:(NSXPCListenerEndpoint *)listener;
- (void)postRuleSyncNotificationWithCustomMessage:(NSString *)message reply:(void (^)(void))reply;

@end

@interface SNTXPCControlInterface : SNTXPCUnprivilegedControlInterface

///
///  Internal method used to initialize the control interface
///

+ (void)initializeControlInterface:(NSXPCInterface *)r;

@end
