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

#import "SNTCommandSyncPreflight.h"

#include "SNTKernelCommon.h"
#include "SNTLogging.h"

#import "SNTCommandSyncStatus.h"
#import "SNTSystemInfo.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@implementation SNTCommandSyncPreflight

+ (void)performSyncInSession:(NSURLSession *)session
                    progress:(SNTCommandSyncStatus *)progress
                  daemonConn:(SNTXPCConnection *)daemonConn
           completionHandler:(void (^)(BOOL success))handler {
  NSURL *url = [NSURL URLWithString:[@"preflight/" stringByAppendingString:progress.machineID]
                      relativeToURL:progress.syncBaseURL];

  NSMutableDictionary *requestDict = [NSMutableDictionary dictionary];
  requestDict[@"serial_no"] = [SNTSystemInfo serialNumber];
  requestDict[@"hostname"] = [SNTSystemInfo shortHostname];
  requestDict[@"santa_version"] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  requestDict[@"os_version"] = [SNTSystemInfo osVersion];
  requestDict[@"os_build"] = [SNTSystemInfo osBuild];
  requestDict[@"primary_user"] = progress.machineOwner;

  NSData *requestBody = [NSJSONSerialization dataWithJSONObject:requestDict
                                                        options:0
                                                          error:nil];
  NSMutableURLRequest *req = [[NSMutableURLRequest alloc] initWithURL:url];
  [req setHTTPMethod:@"POST"];
  [req setHTTPBody:requestBody];

  [[session dataTaskWithRequest:req completionHandler:^(NSData *data,
                                                        NSURLResponse *response,
                                                        NSError *error) {
      long statusCode = [(NSHTTPURLResponse *)response statusCode];
      if (statusCode != 200) {
        LOGD(@"HTTP Response: %@",
             [[NSHTTPURLResponse localizedStringForStatusCode:statusCode] capitalizedString]);
        handler(NO);
      } else {
        NSDictionary *r = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];

        progress.eventBatchSize = [r[@"batch_size"] intValue];
        progress.uploadLogURL = [NSURL URLWithString:r[@"upload_logs_url"]];

        if (r[@"client_mode"]) {
          [[daemonConn remoteObjectProxy] setClientMode:[r[@"client_mode"] intValue] withReply:^{}];
        }

        handler(YES);
      }
  }] resume];
}

@end
