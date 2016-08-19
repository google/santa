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

#import "SNTCommandSyncPreflight.h"

#include "SNTKernelCommon.h"
#include "SNTLogging.h"

#import "SNTCommandSyncConstants.h"
#import "SNTCommandSyncState.h"
#import "SNTConfigurator.h"
#import "SNTSystemInfo.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

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
  [[self.daemonConn remoteObjectProxy] databaseRuleCounts:^(int64_t binary, int64_t certificate) {
    requestDict[kBinaryRuleCount] = @(binary);
    requestDict[kCertificateRuleCount] = @(certificate);
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

  dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));

  // If user requested it or we've never had a successful sync, try from a clean slate.
  if ([[[NSProcessInfo processInfo] arguments] containsObject:@"--clean"] ||
      [[SNTConfigurator configurator] syncCleanRequired]) {
    requestDict[kRequestCleanSync] = @YES;
  }

  NSURLRequest *req = [self requestWithDictionary:requestDict];
  NSDictionary *resp = [self performRequest:req];

  if (!resp) return NO;

  self.syncState.eventBatchSize = [resp[kBatchSize] intValue];
  if (self.syncState.eventBatchSize == 0) {
    self.syncState.eventBatchSize = 50;
  }

  self.syncState.uploadLogURL = [NSURL URLWithString:resp[kUploadLogsURL]];

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
    self.syncState.cleanSync = YES;
  }

  return YES;
}

@end
