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

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/String.h"
#import "Source/santasyncservice/SNTSyncLogging.h"
#import "Source/santasyncservice/SNTSyncState.h"

#include <google/protobuf/arena.h>
#include "Source/santasyncservice/syncv1.pb.h"
namespace pbv1 = ::santa::sync::v1;

using santa::NSStringToUTF8String;

@implementation SNTSyncPostflight

- (NSURL *)stageURL {
  NSString *stageName = [@"postflight" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  google::protobuf::Arena arena;
  auto req = google::protobuf::Arena::Create<::pbv1::PostflightRequest>(&arena);
  req->set_machine_id(NSStringToUTF8String(self.syncState.machineID));
  req->set_rules_received(static_cast<uint32_t>(self.syncState.rulesReceived));
  req->set_rules_processed(static_cast<uint32_t>(self.syncState.rulesProcessed));

  id<SNTDaemonControlXPC> rop = [self.daemonConn synchronousRemoteObjectProxy];
  [rop databaseRulesHash:^(NSString *hash) {
    req->set_rules_hash(NSStringToUTF8String(hash));
  }];

  ::pbv1::PostflightResponse response;
  [self performRequest:[self requestWithMessage:req] intoMessage:&response timeout:30];

  // Set client mode if it changed
  if (self.syncState.clientMode) {
    [rop setClientMode:self.syncState.clientMode
                 reply:^{
                 }];
  }

  // Remove clean sync flag if we did a clean or clean all sync
  if (self.syncState.syncType != SNTSyncTypeNormal) {
    [rop setSyncTypeRequired:SNTSyncTypeNormal
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

  if (self.syncState.overrideFileAccessAction) {
    [rop setOverrideFileAccessAction:self.syncState.overrideFileAccessAction
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
