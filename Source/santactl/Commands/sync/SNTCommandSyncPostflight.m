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

#import "SNTCommandSyncPostflight.h"

#include "SNTLogging.h"

#import "SNTCommandSyncConstants.h"
#import "SNTCommandSyncState.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@implementation SNTCommandSyncPostflight

+ (void)performSyncInSession:(NSURLSession *)session
                   syncState:(SNTCommandSyncState *)syncState
                  daemonConn:(SNTXPCConnection *)daemonConn
           completionHandler:(void (^)(BOOL success))handler {
  NSURL *url = [NSURL URLWithString:[kURLPostflight stringByAppendingString:syncState.machineID]
                      relativeToURL:syncState.syncBaseURL];
  NSMutableURLRequest *req = [[NSMutableURLRequest alloc] initWithURL:url];
  [req setHTTPMethod:@"POST"];

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
      NSDictionary *r = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];

      if (syncState.newClientMode) {
        [[daemonConn remoteObjectProxy] setClientMode:syncState.newClientMode reply:^{}];
      }

      NSString *backoffInterval = r[kBackoffInterval];
      if (backoffInterval) {
        [[daemonConn remoteObjectProxy] setNextSyncInterval:[backoffInterval intValue] reply:^{}];
      }

      if (syncState.cleanSync) {
        [[daemonConn remoteObjectProxy] setSyncCleanRequired:NO reply:^{}];
      }

      // Update last sync success
      [[daemonConn remoteObjectProxy] setSyncLastSuccess:[NSDate date] reply:^{}];

      handler(YES);
    }
  }] resume];
}


@end
