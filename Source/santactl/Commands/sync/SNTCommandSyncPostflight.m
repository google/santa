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

- (NSURL *)stageURL {
  NSString *stageName = [@"postflight" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  [self performRequest:[self requestWithDictionary:nil]];

  dispatch_group_t group = dispatch_group_create();
  void (^replyBlock)() = ^{
    dispatch_group_leave(group);
  };

  // Set client mode if it changed
  if (self.syncState.clientMode) {
    dispatch_group_enter(group);
    [[self.daemonConn remoteObjectProxy] setClientMode:self.syncState.clientMode
                                                 reply:replyBlock];
  }

  // Remove clean sync flag if we did a clean sync
  if (self.syncState.cleanSync) {
    dispatch_group_enter(group);
    [[self.daemonConn remoteObjectProxy] setSyncCleanRequired:NO reply:replyBlock];
  }

  // Update whitelist/blacklist regexes
  if (self.syncState.whitelistRegex) {
    dispatch_group_enter(group);
    [[self.daemonConn remoteObjectProxy] setWhitelistPathRegex:self.syncState.whitelistRegex
                                                         reply:replyBlock];
  }
  if (self.syncState.blacklistRegex) {
    dispatch_group_enter(group);
    [[self.daemonConn remoteObjectProxy] setBlacklistPathRegex:self.syncState.blacklistRegex
                                                         reply:replyBlock];
  }

  // Update last sync success
  dispatch_group_enter(group);
  [[self.daemonConn remoteObjectProxy] setSyncLastSuccess:[NSDate date] reply:replyBlock];

  // Wait for dispatch group
  dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

  return YES;
}

@end
