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
#import "SNTStoredEvent.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

#include "SNTLogging.h"

@implementation SNTCommandSyncRuleDownload

- (NSURL *)stageURL {
  NSString *stageName = [@"ruledownload" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  // Grab the new rules from server
  NSArray<SNTRule *> *newRules = [self downloadNewRulesFromServer];
  if (!newRules) return NO;        // encountered a problem with the download
  if (!newRules.count) return YES; // successfully downloaded rules, but nothing of interest

  // Tell santad to add the new rules to the database.
  // Wait until finished or until 5 minutes pass.
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block NSError *error;
  [[self.daemonConn remoteObjectProxy] databaseRuleAddRules:newRules
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

  // Tell santad to record a successful rules sync and wait for it to finish.
  sema = dispatch_semaphore_create(0);
  [[self.daemonConn remoteObjectProxy] setRuleSyncLastSuccess:[NSDate date]
                                                        reply:^{
    dispatch_semaphore_signal(sema);
  }];
  dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

  LOGI(@"Added %lu rules", newRules.count);

  // Send out push notifications about any newly whitelisted binaries
  // that had been previously blocked by santad.
  [self announceUnblockingRules:newRules];

  return YES;
}

// Downloads new rules from server and converts them into SNTRule.
// Returns an array of all converted rules, or nil if there was a server problem.
// Note that rules from the server are filtered.  We only keep those whose rule_type
// is either BINARY or CERTIFICATE.  PACKAGE rules are dropped.
- (NSArray<SNTRule *> *)downloadNewRulesFromServer {
  NSMutableArray<SNTRule *> *newRules = [NSMutableArray array];
  NSString *cursor = nil;
  do {
    NSDictionary *requestDict = cursor ? @{kCursor : cursor} : @{};
    NSDictionary *response = [self performRequest:[self requestWithDictionary:requestDict]];
    if (!response) return nil;
    for (NSDictionary *ruleDict in response[kRules]) {
      SNTRule *rule = [self ruleFromDictionary:ruleDict];
      if (rule) [newRules addObject:rule];
    }
    cursor = response[kCursor];
  } while (cursor);
  return newRules;
}

// Sends push notification for each rule in newRules that whitelists a binary
// recently blocked by santad.
- (void)announceUnblockingRules:(NSArray<SNTRule *> *)newRules {
  if (!self.syncState.targetedRuleSync) return;
  for (SNTRule *rule in newRules) {
    // Ignore rules that aren't related to whitelisting a binary.
    if (rule.type != SNTRuleTypeBinary || rule.state != SNTRuleStateWhitelist) continue;
    // Check to see if the rule corresponds to a recently blocked binary.
    [[self.daemonConn remoteObjectProxy] recentlyBlockedEventWithSHA256:rule.shasum
                                                                  reply:^(SNTStoredEvent *se) {
      if (!se) return; // couldn't find a matching blocking event
      NSString *name = se.fileBundleName ?: se.filePath;
      NSString *message = [NSString stringWithFormat:@"%@ can now be run", name];
      [[self.daemonConn remoteObjectProxy]
       postRuleSyncNotificationWithCustomMessage:message reply:^{}];
    }];
  }
}

- (SNTRule *)ruleFromDictionary:(NSDictionary *)dict {
  if (!dict) return nil;

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
