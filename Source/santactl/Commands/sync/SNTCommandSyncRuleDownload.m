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
  [self.syncState.whitelistNotificationQueue addOperationWithBlock:^{
    [self announceUnblockingRules:newRules];
  }];

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

// Send out push notifications for whitelisted bundles/binaries whose rule download was preceded by
// an associated announcing FCM message.
- (void)announceUnblockingRules:(NSArray<SNTRule *> *)newRules {
  if (!self.syncState.targetedRuleSync) return;

  for (NSString *key in self.syncState.whitelistNotifications) {
    // Each notifier object is a dictionary with @"name" and @"count" keys. If the count has been
    // decremented to zero, then this means that we have downloaded all of the rules associated with
    // this SHA256 hash (which might be a bundle hash or a binary hash), in which case we are OK to
    // show a notification that the named bundle/binary can be run.
    NSDictionary *notifier = self.syncState.whitelistNotifications[key];
    NSNumber *count = notifier[kFileBundleBinaryCount];
    if (count && [count intValue] == 0) {
      NSString *message = [NSString stringWithFormat:@"%@ can now be run", notifier[kFileName]];
      [[self.daemonConn remoteObjectProxy]
          postRuleSyncNotificationWithCustomMessage:message reply:^{}];
    }
  }
}


// Converts rule information downloaded from the server into a SNTRule.  Because any information
// not recorded by SNTRule is thrown away here, this method is also responsible for dealing with
// the extra bundle rule information (bundle_hash & rule_count).
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

  // Check rule for extra notification related info.
  //
  // Q: Is the count value sent down with the initial FCM message? Or in each rule?
  // A: In each rule.
  //
  // Q: What happens if the rules get sent before the corresponding FCM message?
  // A: No notifier object is ever created; user won't receive notification.
  if (newRule.state == SNTRuleStateWhitelist) {
    // primaryHash is the bundle hash if there was a bundle hash included in the rule, otherwise
    // it is simply the binary hash.
    NSString *primaryHash = dict[kRuleBundleHash];
    if (primaryHash.length != 64) {
      primaryHash = newRule.shasum;
    }

    // If we have already seen a rule with the same primary hash, then decrement the count of the
    // corresponding pending notification.  Otherwise, if this is the first time we've seen this
    // primary hash, add a count field to the pending notfication and set its initial value.
    // If the downloaded rule included count information, this initial value is (count - 1).
    // If the downloaded rule had no count information, then it was a non-bundle rule and count is
    // set to 0, indicating that the we've already downloaded all of the 1 rules associated with
    // the binary.
    [self.syncState.whitelistNotificationQueue addOperationWithBlock:^{
      NSMutableDictionary *notifier = self.syncState.whitelistNotifications[primaryHash];
      if (notifier) {
        NSNumber *ruleCount = dict[kFileBundleBinaryCount];
        NSNumber *notifierCount = notifier[kFileBundleBinaryCount];
        if (notifierCount) {  // bundle rule with existing count
          notifier[kFileBundleBinaryCount] = @([notifierCount intValue] - 1);
        } else if (ruleCount) {  // bundle rule seen for first time
          notifier[kFileBundleBinaryCount] = @([ruleCount intValue] - 1);
        } else {  // non-bundle binary rule
          notifier[kFileBundleBinaryCount] = @0;
        }
      }
    }];
  }

  return newRule;
}

@end
