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

#import "Source/santactl/Commands/sync/SNTCommandSyncPreflight.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTKernelCommon.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/Commands/sync/SNTCommandSyncConstants.h"
#import "Source/santactl/Commands/sync/SNTCommandSyncState.h"

@implementation SNTCommandSyncPreflight

- (NSURL *)stageURL {
  NSString *stageName = [@"preflight" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  NSMutableDictionary *requestDict = [NSMutableDictionary dictionary];
  requestDict[kSerialNumber] = [SNTSystemInfo serialNumber];
  requestDict[kHostname] = [SNTSystemInfo longHostname];
  requestDict[kOSVer] = [SNTSystemInfo osVersion];
  requestDict[kOSBuild] = [SNTSystemInfo osBuild];
  requestDict[kSantaVer] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  requestDict[kPrimaryUser] = self.syncState.machineOwner;

  dispatch_group_t group = dispatch_group_create();
  dispatch_group_enter(group);
  [[self.daemonConn remoteObjectProxy] databaseRuleCounts:^(int64_t binary,
                                                            int64_t certificate,
                                                            int64_t compiler,
                                                            int64_t transitive) {
    requestDict[kBinaryRuleCount] = @(binary);
    requestDict[kCertificateRuleCount] = @(certificate);
    requestDict[kCompilerRuleCount] = @(compiler);
    requestDict[kTransitiveRuleCount] = @(transitive);
    dispatch_group_leave(group);
  }];

  dispatch_group_enter(group);
  [[self.daemonConn remoteObjectProxy] clientMode:^(SNTClientMode cm) {
    switch (cm) {
      case SNTClientModeMonitor:
        requestDict[kClientMode] = kClientModeMonitor; break;
      case SNTClientModeLockdown:
        requestDict[kClientMode] = kClientModeLockdown; break;
      default: break;
    }
    dispatch_group_leave(group);
  }];

  __block BOOL syncClean = NO;
  dispatch_group_enter(group);
  [[self.daemonConn remoteObjectProxy] syncCleanRequired:^(BOOL clean) {
    syncClean = clean;
    dispatch_group_leave(group);
  }];

  dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));

  // If user requested it or we've never had a successful sync, try from a clean slate.
  if ([[[NSProcessInfo processInfo] arguments] containsObject:@"--clean"] || syncClean) {
    LOGD(@"Clean sync requested by user");
    requestDict[kRequestCleanSync] = @YES;
  }

  NSURLRequest *req = [self requestWithDictionary:requestDict];
  NSDictionary *resp = [self performRequest:req];

  if (!resp) return NO;

  dispatch_group_enter(group);
  NSNumber *enableBundles = resp[kEnableBundles];
  if (!enableBundles) {
    enableBundles = resp[kEnableBundles_OLD];
  }
  [[self.daemonConn remoteObjectProxy] setEnableBundles:[enableBundles boolValue] reply:^{
    dispatch_group_leave(group);
  }];

  dispatch_group_enter(group);
  NSNumber *enableTransitiveWhitelisting = resp[kEnableTransitiveWhitelisting];
  if (!enableTransitiveWhitelisting) {
    enableTransitiveWhitelisting = resp[kEnableTransitiveWhitelisting_OLD];
  }
  BOOL enabled = [enableTransitiveWhitelisting boolValue];
  [[self.daemonConn remoteObjectProxy] setEnableTransitiveWhitelisting:enabled reply:^{
    dispatch_group_leave(group);
  }];

  self.syncState.eventBatchSize = [resp[kBatchSize] unsignedIntegerValue] ?: kDefaultEventBatchSize;
  self.syncState.FCMToken = resp[kFCMToken];

  // Don't let these go too low
  NSUInteger value = [resp[kFCMFullSyncInterval] unsignedIntegerValue];
  self.syncState.FCMFullSyncInterval =
      (value < kDefaultFullSyncInterval) ? kDefaultFCMFullSyncInterval : value;
  value = [resp[kFCMGlobalRuleSyncDeadline] unsignedIntegerValue];
  self.syncState.FCMGlobalRuleSyncDeadline =
      (value < 60) ?  kDefaultFCMGlobalRuleSyncDeadline : value;

  if ([resp[kClientMode] isEqual:kClientModeMonitor]) {
    self.syncState.clientMode = SNTClientModeMonitor;
  } else if ([resp[kClientMode] isEqual:kClientModeLockdown]) {
    self.syncState.clientMode = SNTClientModeLockdown;
  }

  if ([resp[kWhitelistRegex] isKindOfClass:[NSString class]]) {
    self.syncState.whitelistRegex = resp[kWhitelistRegex];
  }

  if ([resp[kBlacklistRegex] isKindOfClass:[NSString class]]) {
    self.syncState.blacklistRegex = resp[kBlacklistRegex];
  }

  if ([resp[kCleanSync] boolValue]) {
    LOGD(@"Clean sync requested by server");
    self.syncState.cleanSync = YES;
  }

  dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
  return YES;
}

@end
