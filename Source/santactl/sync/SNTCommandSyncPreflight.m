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
#import "SNTSystemInfo.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@implementation SNTCommandSyncPreflight

+ (void)performSyncInSession:(NSURLSession *)session
                   syncState:(SNTCommandSyncState *)syncState
                  daemonConn:(SNTXPCConnection *)daemonConn
           completionHandler:(void (^)(BOOL success))handler {
  NSURL *url = [NSURL URLWithString:[kURLPreflight stringByAppendingString:syncState.machineID]
                      relativeToURL:syncState.syncBaseURL];

  NSMutableDictionary *requestDict = [NSMutableDictionary dictionary];
  requestDict[kSerialNumber] = [SNTSystemInfo serialNumber];
  requestDict[kHostname] = [SNTSystemInfo shortHostname];
  requestDict[kSantaVer] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  requestDict[kOSVer] = [SNTSystemInfo osVersion];
  requestDict[kOSBuild] = [SNTSystemInfo osBuild];
  requestDict[kPrimaryUser] = syncState.machineOwner;

  if ([[[NSProcessInfo processInfo] arguments] containsObject:@"--clean"]) {
    requestDict[kRequestCleanSync] = @YES;
  }

  NSData *requestBody = [NSJSONSerialization dataWithJSONObject:requestDict
                                                        options:0
                                                          error:nil];
  NSMutableURLRequest *req = [[NSMutableURLRequest alloc] initWithURL:url];
  [req setHTTPMethod:@"POST"];
  [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
  [req setHTTPBody:requestBody];

  [[session dataTaskWithRequest:req completionHandler:^(NSData *data,
                                                        NSURLResponse *response,
                                                        NSError *error) {
      long statusCode = [(NSHTTPURLResponse *)response statusCode];
      if (statusCode != 200) {
        LOGE(@"HTTP Response: %d %@",
             statusCode,
             [[NSHTTPURLResponse localizedStringForStatusCode:statusCode] capitalizedString]);
        handler(NO);
      } else {
        NSDictionary *r = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];

        syncState.eventBatchSize = [r[kBatchSize] intValue];
        syncState.uploadLogURL = [NSURL URLWithString:r[kUploadLogsURL]];

        if ([r[kClientMode] isEqual:kClientModeMonitor]) {
            [[daemonConn remoteObjectProxy] setClientMode:CLIENTMODE_MONITOR reply:^{}];
        } else if ([r[kClientMode] isEqual:kClientModeLockdown]) {
            [[daemonConn remoteObjectProxy] setClientMode:CLIENTMODE_LOCKDOWN reply:^{}];
        }

        if ([r[kCleanSync] boolValue]) {
          syncState.cleanSync = YES;
          LOGD(@"Clean sync requested by server");
        }

        handler(YES);
      }
  }] resume];
}

@end
