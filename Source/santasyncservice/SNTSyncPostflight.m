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

#import "Source/santasyncservice/SNTSyncPostflight.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santasyncservice/SNTSyncState.h"

@implementation SNTSyncPostflight

- (NSURL *)stageURL {
  NSString *stageName = [@"postflight" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  [self performRequest:[self requestWithDictionary:nil]];

  id<SNTDaemonControlXPC> rop = [self.daemonConn synchronousRemoteObjectProxy];

  // Set client mode if it changed
  if (self.syncState.clientMode) {
    [rop setClientMode:self.syncState.clientMode
                 reply:^{
                 }];
  }

  // Remove clean sync flag if we did a clean sync
  if (self.syncState.cleanSync) {
    [rop setSyncCleanRequired:NO
                        reply:^{
                        }];
  }

  // Update allowlist/blocklist regexes
  if (self.syncState.allowlistRegex) {
    [rop setAllowedPathRegex:self.syncState.allowlistRegex
                       reply:^{
                       }];
  }
  if (self.syncState.blocklistRegex) {
    [rop setBlockedPathRegex:self.syncState.blocklistRegex
                       reply:^{
                       }];
  }

  if (self.syncState.blockUSBMount != nil) {
    [rop setBlockUSBMount:[self.syncState.blockUSBMount boolValue]
                    reply:^{
                    }];
  }
  if (self.syncState.remountUSBMode) {
    [rop setRemountUSBMode:self.syncState.remountUSBMode
                     reply:^{
                     }];
  }

  if (self.syncState.enableBundles) {
    [rop setEnableBundles:[self.syncState.enableBundles boolValue]
                    reply:^{
                    }];
  }

  if (self.syncState.enableTransitiveRules) {
    [rop setEnableTransitiveRules:[self.syncState.enableTransitiveRules boolValue]
                            reply:^{
                            }];
  }

  if (self.syncState.enableAllEventUpload) {
    [rop setEnableAllEventUpload:[self.syncState.enableAllEventUpload boolValue]
                           reply:^{
                           }];
  }

  if (self.syncState.disableUnknownEventUpload) {
    [rop setDisableUnknownEventUpload:[self.syncState.disableUnknownEventUpload boolValue]
                                reply:^{
                                }];
  }

  // Update last sync success
  [rop setFullSyncLastSuccess:[NSDate date]
                        reply:^{
                        }];

  return YES;
}

@end
