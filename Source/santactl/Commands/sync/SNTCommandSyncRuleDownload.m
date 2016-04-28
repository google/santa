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

+ (void)performSyncInSession:(NSURLSession *)session
                   syncState:(SNTCommandSyncState *)syncState
                  daemonConn:(SNTXPCConnection *)daemonConn
           completionHandler:(void (^)(BOOL success))handler {
  NSURL *url = [NSURL URLWithString:[kURLRuleDownload stringByAppendingString:syncState.machineID]
                      relativeToURL:syncState.syncBaseURL];
  [self ruleDownloadWithCursor:nil
                           url:url
                       session:session
                     syncState:syncState
                    daemonConn:daemonConn
             completionHandler:handler];
}

+ (void)ruleDownloadWithCursor:(NSString *)cursor
                           url:(NSURL *)url
                       session:(NSURLSession *)session
                     syncState:(SNTCommandSyncState *)syncState
                    daemonConn:(SNTXPCConnection *)daemonConn
             completionHandler:(void (^)(BOOL success))handler {
  NSDictionary *requestDict = (cursor ? @{kCursor : cursor} : @{});

  if (!syncState.downloadedRules) {
    syncState.downloadedRules = [NSMutableArray array];
  }

  NSMutableURLRequest *req = [[NSMutableURLRequest alloc] initWithURL:url];
  [req setHTTPBody:[NSJSONSerialization dataWithJSONObject:requestDict
                                                   options:0
                                                     error:nil]];
  [req setHTTPMethod:@"POST"];
  [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
  [[session dataTaskWithRequest:req completionHandler:^(NSData *data,
                                                        NSURLResponse *response,
                                                        NSError *error) {
    long statusCode = [(NSHTTPURLResponse *)response statusCode];
    if (statusCode != 200) {
      LOGE(@"HTTP Response: %ld %@",
           statusCode,
           [[NSHTTPURLResponse localizedStringForStatusCode:statusCode] capitalizedString]);
      LOGD(@"%@", error);
      handler(NO);
    } else {
      NSDictionary *resp = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
      if (!resp) {
        LOGE(@"Failed to decode server's response");
        handler(NO);
        return;
      }

      NSArray *receivedRules = resp[kRules];
      for (NSDictionary *rule in receivedRules) {
        SNTRule *r = [self ruleFromDictionary:rule];
        if (r) [syncState.downloadedRules addObject:r];
      }

      if (resp[kCursor]) {
        [self ruleDownloadWithCursor:resp[kCursor]
                                 url:url
                             session:session
                           syncState:syncState
                          daemonConn:daemonConn
                   completionHandler:handler];
      } else {
        if (syncState.downloadedRules.count) {
          [[daemonConn remoteObjectProxy] databaseRuleAddRules:syncState.downloadedRules
                                                    cleanSlate:syncState.cleanSync
                                                         reply:^(NSError *error) {
            if (!error) {
              LOGI(@"Added %lu rule(s)", syncState.downloadedRules.count);
              handler(YES);
            } else {
              LOGE(@"Failed to add rule(s) to database: %@", error.localizedDescription);
              LOGD(@"Failure reason: %@", error.localizedFailureReason);
              handler(NO);
            }
          }];
        } else {
          handler(YES);
        }
      }
    }
  }] resume];
}

+ (SNTRule *)ruleFromDictionary:(NSDictionary *)dict {
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
