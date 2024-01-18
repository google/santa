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

#import "Source/santasyncservice/SNTSyncPreflight.h"
#include "Source/common/SNTCommonEnums.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santasyncservice/SNTSyncLogging.h"
#import "Source/santasyncservice/SNTSyncState.h"

// Return the given value or nil if not of the expected given class
static id EnsureType(id val, Class c) {
  if ([val isKindOfClass:c]) {
    return val;
  } else {
    return nil;
  }
}

@implementation SNTSyncPreflight

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
  requestDict[kModelIdentifier] = [SNTSystemInfo modelIdentifier];
  requestDict[kSantaVer] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  requestDict[kPrimaryUser] = self.syncState.machineOwner;
  if (self.syncState.pushNotificationsToken) {
    requestDict[kFCMToken] = self.syncState.pushNotificationsToken;
  }

  id<SNTDaemonControlXPC> rop = [self.daemonConn synchronousRemoteObjectProxy];

  // dispatch_group_t group = dispatch_group_create();
  // dispatch_group_enter(group);
  [rop databaseRuleCounts:^(int64_t binary, int64_t certificate, int64_t compiler,
                            int64_t transitive, int64_t teamID, int64_t signingID) {
    requestDict[kBinaryRuleCount] = @(binary);
    requestDict[kCertificateRuleCount] = @(certificate);
    requestDict[kCompilerRuleCount] = @(compiler);
    requestDict[kTransitiveRuleCount] = @(transitive);
    requestDict[kTeamIDRuleCount] = @(teamID);
    requestDict[kSigningIDRuleCount] = @(signingID);
  }];

  [rop clientMode:^(SNTClientMode cm) {
    switch (cm) {
      case SNTClientModeMonitor: requestDict[kClientMode] = kClientModeMonitor; break;
      case SNTClientModeLockdown: requestDict[kClientMode] = kClientModeLockdown; break;
      default: break;
    }
  }];

  __block SNTSyncType requestSyncType = SNTSyncTypeNormal;
  [rop syncTypeRequired:^(SNTSyncType syncTypeRequired) {
    requestSyncType = syncTypeRequired;
  }];

  // If user requested it or we've never had a successful sync, try from a clean slate.
  if (requestSyncType == SNTSyncTypeClean) {
    SLOGD(@"Clean sync requested by user");
    requestDict[kRequestCleanSync] = @YES;
  } else if (requestSyncType == SNTSyncTypeCleanAll) {
    SLOGD(@"Clean All sync requested by user");
    requestDict[kRequestCleanAllSync] = @YES;
  }

  NSURLRequest *req = [self requestWithDictionary:requestDict];
  NSDictionary *resp = [self performRequest:req];

  if (!resp) return NO;

  self.syncState.enableBundles = EnsureType(resp[kEnableBundles], [NSNumber class])
                                   ?: EnsureType(resp[kEnableBundlesDeprecated], [NSNumber class]);
  self.syncState.enableTransitiveRules = EnsureType(resp[kEnableTransitiveRules], [NSNumber class])
                                   ?: EnsureType(resp[kEnableTransitiveRulesDeprecated], [NSNumber class])
                                   ?: EnsureType(resp[kEnableTransitiveRulesSuperDeprecated], [NSNumber class]);
  self.syncState.enableAllEventUpload = EnsureType(resp[kEnableAllEventUpload], [NSNumber class]);
  self.syncState.disableUnknownEventUpload =
    EnsureType(resp[kDisableUnknownEventUpload], [NSNumber class]);

  self.syncState.eventBatchSize =
    [EnsureType(resp[kBatchSize], [NSNumber class]) unsignedIntegerValue] ?: kDefaultEventBatchSize;

  // Don't let these go too low
  NSUInteger value =
    [EnsureType(resp[kFCMFullSyncInterval], [NSNumber class]) unsignedIntegerValue];
  self.syncState.pushNotificationsFullSyncInterval =
    (value < kDefaultFullSyncInterval) ? kDefaultPushNotificationsFullSyncInterval : value;

  value = [EnsureType(resp[kFCMGlobalRuleSyncDeadline], [NSNumber class]) unsignedIntegerValue];
  self.syncState.pushNotificationsGlobalRuleSyncDeadline =
    (value < 60) ? kDefaultPushNotificationsGlobalRuleSyncDeadline : value;

  // Check if our sync interval has changed
  value = [EnsureType(resp[kFullSyncInterval], [NSNumber class]) unsignedIntegerValue];
  self.syncState.fullSyncInterval = (value < 60) ? kDefaultFullSyncInterval : value;

  if ([resp[kClientMode] isEqual:kClientModeMonitor]) {
    self.syncState.clientMode = SNTClientModeMonitor;
  } else if ([resp[kClientMode] isEqual:kClientModeLockdown]) {
    self.syncState.clientMode = SNTClientModeLockdown;
  }

  self.syncState.allowlistRegex =
    EnsureType(resp[kAllowedPathRegex], [NSString class])
      ?: EnsureType(resp[kAllowedPathRegexDeprecated], [NSString class]);

  self.syncState.blocklistRegex =
    EnsureType(resp[kBlockedPathRegex], [NSString class])
      ?: EnsureType(resp[kBlockedPathRegexDeprecated], [NSString class]);

  self.syncState.blockUSBMount = EnsureType(resp[kBlockUSBMount], [NSNumber class]);
  self.syncState.remountUSBMode = EnsureType(resp[kRemountUSBMode], [NSArray class]);

  self.syncState.overrideFileAccessAction =
    EnsureType(resp[kOverrideFileAccessAction], [NSString class]);

  // Default sync type is SNTSyncTypeNormal
  self.syncState.syncType = SNTSyncTypeNormal;

  if ([EnsureType(resp[kCleanSyncDeprecated], [NSNumber class]) boolValue]) {
    self.syncState.syncType = SNTSyncTypeClean;
  }

  // If kSyncType response key exists, it overrides the kCleanSyncDeprecated value
  NSString *responseSyncType = [EnsureType(resp[kSyncType], [NSString class]) lowercaseString];
  if ([responseSyncType isEqualToString:@"clean"]) {
    self.syncState.syncType = SNTSyncTypeClean;
  } else if ([responseSyncType isEqualToString:@"clean_all"]) {
    self.syncState.syncType = SNTSyncTypeCleanAll;
  }

  if (self.syncState.syncType != SNTSyncTypeClean) {
    SLOGD(@"Clean sync requested by server");
  } else if (self.syncState.syncType != SNTSyncTypeCleanAll) {
    SLOGD(@"Clean All sync requested by server");
  }

  return YES;
}

@end
