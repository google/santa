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
  if (requestSyncType == SNTSyncTypeClean || requestSyncType == SNTSyncTypeCleanAll) {
    SLOGD(@"%@ sync requested by user",
          (requestSyncType == SNTSyncTypeCleanAll) ? @"Clean All" : @"Clean");
    requestDict[kRequestCleanSync] = @YES;
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
  //
  // Logic overview:
  // The requested sync type (clean or normal) is merely informative. The server
  // can choose to respond with a normal, clean or clean_all.
  //
  // If the server responds that it will perform a clean sync, santa will
  // treat it as either a clean or clean_all depending on which was requested.
  //
  // The server can also "override" the requested clean operation. If a normal
  // sync was requested, but the server responded that it was doing a clean or
  // clean_all sync, that will take precedence. Similarly, if only a clean sync
  // was requested, the server can force a "clean_all" operation to take place.
  self.syncState.syncType = SNTSyncTypeNormal;

  // If kSyncType response key exists, it overrides the kCleanSyncDeprecated value
  // First check if the kSyncType reponse key exists. If so, it takes precedence
  // over the kCleanSyncDeprecated key.
  NSString *responseSyncType = [EnsureType(resp[kSyncType], [NSString class]) lowercaseString];
  if (responseSyncType) {
    if ([responseSyncType isEqualToString:@"clean"]) {
      // If the client wants to Clean All, this takes precedence. The server
      // cannot override the client wanting to remove all rules.
      if (requestSyncType == SNTSyncTypeCleanAll) {
        self.syncState.syncType = SNTSyncTypeCleanAll;
      } else {
        self.syncState.syncType = SNTSyncTypeClean;
      }
    } else if ([responseSyncType isEqualToString:@"clean_all"]) {
      self.syncState.syncType = SNTSyncTypeCleanAll;
    }
  } else if ([EnsureType(resp[kCleanSyncDeprecated], [NSNumber class]) boolValue]) {
    // If the deprecated key is set, the type of sync clean performed should be
    // the type that was requested. This must be set appropriately so that it
    // can be propagated during the Rule Download stage so SNTRuleTable knows
    // which rules to delete.
    if (requestSyncType == SNTSyncTypeCleanAll) {
      self.syncState.syncType = SNTSyncTypeCleanAll;
    } else {
      self.syncState.syncType = SNTSyncTypeClean;
    }
  }

  if (self.syncState.syncType != SNTSyncTypeNormal) {
    SLOGD(@"Clean sync requested by server");
  }

  return YES;
}

@end
