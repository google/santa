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

#import "SNTCommandSyncRuleDownload.h"

#import "SNTCommandSyncConstants.h"
#import "SNTCommandSyncState.h"
#import "SNTRule.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

#include "SNTLogging.h"

@implementation SNTCommandSyncRuleDownload

- (NSURL *)stageURL {
  NSString *stageName = [@"ruledownload" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  self.syncState.downloadedRules = [NSMutableArray array];
  return [self ruleDownloadWithCursor:nil];
}

- (BOOL)ruleDownloadWithCursor:(NSString *)cursor {
  NSDictionary *requestDict = (cursor ? @{kCursor : cursor} : @{});

  NSDictionary *resp = [self performRequest:[self requestWithDictionary:requestDict]];
  if (!resp) return NO;

  for (NSDictionary *rule in resp[kRules]) {
    SNTRule *r = [self ruleFromDictionary:rule];
    if (r) [self.syncState.downloadedRules addObject:r];
  }

  if (resp[kCursor]) {
    return [self ruleDownloadWithCursor:resp[kCursor]];
  }

  if (!self.syncState.downloadedRules.count) return YES;

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block NSError *error;
  [[self.daemonConn remoteObjectProxy] databaseRuleAddRules:self.syncState.downloadedRules
                                                 cleanSlate:self.syncState.cleanSync
                                                      reply:^(NSError *e) {
    error = e;
    dispatch_semaphore_signal(sema);
  }];
  dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 300 * NSEC_PER_SEC));

  if (error) {
    LOGE(@"Failed to add rule(s) to database: %@", error.localizedDescription);
    LOGD(@"Failure reason: %@", error.localizedFailureReason);
    return NO;
  }

  LOGI(@"Added %lu rules", self.syncState.downloadedRules.count);

  if (self.syncState.targetedRuleSync) {
    NSString *fileName;
    for (SNTRule *r in self.syncState.downloadedRules) {
      fileName = [[self.syncState.ruleSyncCache objectForKey:r.shasum] copy];
      [self.syncState.ruleSyncCache removeObjectForKey:r.shasum];
      if (fileName) break;
    }
    NSString *message = fileName ? [NSString stringWithFormat:@"%@ can now be run", fileName] : nil;
    [[self.daemonConn remoteObjectProxy]
        postRuleSyncNotificationWithCustomMessage:message reply:^{}];
  }

  return YES;
}

- (SNTRule *)ruleFromDictionary:(NSDictionary *)dict {
  if (![dict isKindOfClass:[NSDictionary class]]) return nil;

  SNTRule *newRule = [[SNTRule alloc] init];
  newRule.shasum = dict[kRuleSHA256];
  if (newRule.shasum.length != 64) return nil;

  NSString *policyString = dict[kRulePolicy];
  if ([policyString isEqual:kRulePolicyWhitelist]) {
    newRule.state = SNTRuleStateWhitelist;
  } else if ([policyString isEqual:kRulePolicyBlacklist]) {
    newRule.state = SNTRuleStateBlacklist;
  } else if ([policyString isEqual:kRulePolicySilentBlacklist]) {
    newRule.state = SNTRuleStateSilentBlacklist;
  } else if ([policyString isEqual:kRulePolicyRemove]) {
    newRule.state = SNTRuleStateRemove;
  } else {
    return nil;
  }

  NSString *ruleTypeString = dict[kRuleType];
  if ([ruleTypeString isEqual:kRuleTypeBinary]) {
    newRule.type = SNTRuleTypeBinary;
  } else if ([ruleTypeString isEqual:kRuleTypeCertificate]) {
    newRule.type = SNTRuleTypeCertificate;
  } else {
    return nil;
  }

  NSString *customMsg = dict[kRuleCustomMsg];
  if (customMsg.length) {
    newRule.customMsg = customMsg;
  }

  return newRule;
}

@end
