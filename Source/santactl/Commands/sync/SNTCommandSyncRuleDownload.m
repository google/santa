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

#import "Source/santactl/Commands/sync/SNTCommandSyncRuleDownload.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/Commands/sync/SNTCommandSyncConstants.h"
#import "Source/santactl/Commands/sync/SNTCommandSyncState.h"

@implementation SNTCommandSyncRuleDownload

- (NSURL *)stageURL {
  NSString *stageName = [@"ruledownload" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  // Grab the new rules from server
  NSArray<SNTRule *> *newRules = [self downloadNewRulesFromServer];
  if (!newRules) return NO;         // encountered a problem with the download
  if (!newRules.count) return YES;  // successfully completed request, but no new rules

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
  [[self.daemonConn remoteObjectProxy] setRuleSyncLastSuccess:[NSDate date] reply:^{
    dispatch_semaphore_signal(sema);
  }];
  dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

  LOGI(@"Added %lu rules", newRules.count);

  // Send out push notifications about any newly allowed binaries
  // that had been previously blocked by santad.
  [self.syncState.allowlistNotificationQueue addOperationWithBlock:^{
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

    if (![response isKindOfClass:[NSDictionary class]] ||
        ![response[kRules] isKindOfClass:[NSArray class]]) {
      return nil;
    }

    for (NSDictionary *ruleDict in response[kRules]) {
      SNTRule *rule = [self ruleFromDictionary:ruleDict];
      if (rule) [newRules addObject:rule];
    }
    cursor = response[kCursor];
  } while (cursor);
  return newRules;
}

// Send out push notifications for allowed bundles/binaries whose rule download was preceded by
// an associated announcing FCM message.
- (void)announceUnblockingRules:(NSArray<SNTRule *> *)newRules {
  if (!self.syncState.targetedRuleSync) return;

  NSMutableArray *processed = [NSMutableArray array];

  for (NSString *key in self.syncState.allowlistNotifications) {
    // Each notifier object is a dictionary with name and count keys. If the count has been
    // decremented to zero, then this means that we have downloaded all of the rules associated with
    // this SHA256 hash (which might be a bundle hash or a binary hash), in which case we are OK to
    // show a notification that the named bundle/binary can be run.
    NSDictionary *notifier = self.syncState.allowlistNotifications[key];
    NSNumber *remaining = notifier[kFileBundleBinaryCount];
    if (remaining && [remaining intValue] == 0) {
      [processed addObject:key];
      NSString *message = [NSString stringWithFormat:@"%@ can now be run", notifier[kFileName]];
      [[self.daemonConn remoteObjectProxy]
          postRuleSyncNotificationWithCustomMessage:message reply:^{}];
    }
  }

  // Remove all entries from allowlistNotifications dictionary that had zero count.
  [self.syncState.allowlistNotifications removeObjectsForKeys:processed];
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
  if ([policyString isEqual:kRulePolicyAllowlist] ||
      [policyString isEqual:kRulePolicyAllowlistDeprecated]) {
    newRule.state = SNTRuleStateAllow;
  } else if ([policyString isEqual:kRulePolicyAllowlistCompiler] ||
             [policyString isEqual:kRulePolicyAllowlistCompilerDeprecated]) {
    newRule.state = SNTRuleStateAllowCompiler;
  } else if ([policyString isEqual:kRulePolicyBlocklist] ||
             [policyString isEqual:kRulePolicyBlocklistDeprecated]) {
    newRule.state = SNTRuleStateBlock;
  } else if ([policyString isEqual:kRulePolicySilentBlocklist] ||
             [policyString isEqual:kRulePolicySilentBlocklistDeprecated]) {
    newRule.state = SNTRuleStateSilentBlock;
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
  if (newRule.state == SNTRuleStateAllow || newRule.state == SNTRuleStateAllowCompiler) {
    // primaryHash is the bundle hash if there was a bundle hash included in the rule, otherwise
    // it is simply the binary hash.
    NSString *primaryHash = dict[kFileBundleHash];
    if (primaryHash.length != 64) {
      primaryHash = newRule.shasum;
    }

    // As we read in rules, we update the "remaining count" information stored in
    // allowlistNotifications. This count represents the number of rules associated with the primary
    // hash that still need to be downloaded and added.
    [self.syncState.allowlistNotificationQueue addOperationWithBlock:^{
      NSMutableDictionary *notifier = self.syncState.allowlistNotifications[primaryHash];
      if (notifier) {
        NSNumber *ruleCount = dict[kFileBundleBinaryCount];
        NSNumber *remaining = notifier[kFileBundleBinaryCount];
        if (remaining) {  // bundle rule with existing count
          // If the primary hash already has an associated count field, just decrement it.
          notifier[kFileBundleBinaryCount] = @([remaining intValue] - 1);
        } else if (ruleCount) {  // bundle rule seen for first time
          // Downloaded rules including count information are associated with bundles.
          // The first time we see a rule for a given bundle hash, add a count field with an
          // initial value equal to the number of associated rules, then decrement this value by 1
          // to account for the rule that we've just downloaded.
          notifier[kFileBundleBinaryCount] = @([ruleCount intValue] - 1);
        } else {  // non-bundle binary rule
          // Downloaded rule had no count information, meaning it is a singleton non-bundle rule.
          // Therefore there are no more rules associated with this hash to download.
          notifier[kFileBundleBinaryCount] = @0;
        }
      }
    }];
  }

  return newRule;
}

@end
