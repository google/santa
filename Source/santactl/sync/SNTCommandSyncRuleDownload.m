/// Copyright 2014 Google Inc. All rights reserved.
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

#import "SNTCommandSyncStatus.h"
#import "SNTRule.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

#include "SNTLogging.h"

@implementation SNTCommandSyncRuleDownload

+ (void)performSyncInSession:(NSURLSession *)session
                    progress:(SNTCommandSyncStatus *)progress
                  daemonConn:(SNTXPCConnection *)daemonConn
           completionHandler:(void (^)(BOOL success))handler {
  NSURL *url = [NSURL URLWithString:[@"ruledownload/" stringByAppendingString:progress.machineID]
                      relativeToURL:progress.syncBaseURL];
  [self ruleDownloadWithCursor:nil
                           url:url
                       session:session
                      progress:progress
                    daemonConn:daemonConn
             completionHandler:handler];
}

+ (void)ruleDownloadWithCursor:(NSString *)cursor
                           url:(NSURL *)url
                       session:(NSURLSession *)session
                      progress:(SNTCommandSyncStatus *)progress
                    daemonConn:(SNTXPCConnection *)daemonConn
             completionHandler:(void (^)(BOOL success))handler {

  NSDictionary *requestDict;
  if (cursor) {
    requestDict = @{@"cursor": cursor};
  } else {
    requestDict = @{};
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
      if ([(NSHTTPURLResponse *)response statusCode] != 200) {
        LOGD(@"HTTP Response Code: %d", [(NSHTTPURLResponse *)response statusCode]);
        handler(NO);
      } else {
        NSDictionary *resp = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];

        NSArray *receivedRules = resp[@"rules"];

        if (receivedRules.count == 0) {
          handler(YES);
          return;
        }

        NSMutableArray *rules = [[NSMutableArray alloc] initWithCapacity:receivedRules.count];

        for (NSDictionary *rule in receivedRules) {
          SNTRule *newRule = [[SNTRule alloc] init];
          newRule.shasum = rule[@"sha1"];

          newRule.state = [rule[@"state"] intValue];
          if (newRule.state <= RULESTATE_UNKNOWN || newRule.state >= RULESTATE_MAX) continue;

          newRule.type = [rule[@"type"] intValue];
          if (newRule.type <= RULETYPE_UNKNOWN || newRule.type >= RULETYPE_MAX) continue;

          NSString *customMsg = rule[@"custom_msg"];
          if (customMsg) {
            newRule.customMsg = customMsg;
          }

          [rules addObject:newRule];
        }

        [[daemonConn remoteObjectProxy] databaseRuleAddRules:rules withReply:^{
            LOGI(@"Downloaded %d rule(s)", rules.count);

            if (resp[@"cursor"]) {
              [self ruleDownloadWithCursor:resp[@"cursor"]
                                       url:url
                                   session:session
                                  progress:progress
                                daemonConn:daemonConn
                         completionHandler:handler];
            } else {
              handler(YES);
            }
        }];
      }
  }] resume];
}

@end
