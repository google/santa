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

#import "Source/santasyncservice/SNTSyncPreflight.h"
#include "Source/common/SNTCommonEnums.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/String.h"
#import "Source/santasyncservice/SNTSyncLogging.h"
#import "Source/santasyncservice/SNTSyncState.h"

#include <google/protobuf/arena.h>
#include "Source/santasyncservice/syncv1.pb.h"
namespace pbv1 = ::santa::sync::v1;

using santa::NSStringToUTF8String;
using santa::StringToNSString;

/*

Clean Sync Implementation Notes

The clean sync implementation seems a bit complex at first glance, but boils
down to the following rules:

1. If the server says to do a "clean" sync, a "clean" sync is performed, unless the
   client specified a "clean all" sync, in which case "clean all" is performed.
2. If the server responded that it is performing a "clean all" sync, a "clean all" is performed.
3. All other server responses result in a "normal" sync.

The following table expands upon the above logic to list most of the permutations:

| Client Sync State | Clean Sync Request? | Server Response    | Sync Type Performed |
| ----------------- | ------------------- | ------------------ | ------------------- |
| normal            | No                  | normal OR <empty>  | normal              |
| normal            | No                  | clean              | clean               |
| normal            | No                  | clean_all          | clean_all           |
| normal            | No                  | clean_sync (dep)   | clean               |
| normal            | Yes                 | New AND Dep Key    | Dep key ignored     |
| clean             | Yes                 | normal OR <empty>  | normal              |
| clean             | Yes                 | clean              | clean               |
| clean             | Yes                 | clean_all          | clean_all           |
| clean             | Yes                 | clean_sync (dep)   | clean               |
| clean             | Yes                 | New AND Dep Key    | Dep key ignored     |
| clean_all         | Yes                 | normal OR <empty>  | normal              |
| clean_all         | Yes                 | clean              | clean_all           |
| clean_all         | Yes                 | clean_all          | clean_all           |
| clean_all         | Yes                 | clean_sync (dep)   | clean_all           |
| clean_all         | Yes                 | New AND Dep Key    | Dep key ignored     |

*/
@implementation SNTSyncPreflight

- (NSURL *)stageURL {
  NSString *stageName = [@"preflight" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  google::protobuf::Arena arena;
  auto req = google::protobuf::Arena::Create<::pbv1::PreflightRequest>(&arena);
  req->set_serial_number(NSStringToUTF8String([SNTSystemInfo serialNumber]));
  req->set_hostname(NSStringToUTF8String([SNTSystemInfo longHostname]));
  req->set_os_version(NSStringToUTF8String([SNTSystemInfo osVersion]));
  req->set_os_build(NSStringToUTF8String([SNTSystemInfo osBuild]));
  req->set_model_identifier(NSStringToUTF8String([SNTSystemInfo modelIdentifier]));
  req->set_santa_version(
    NSStringToUTF8String([[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"]));
  req->set_primary_user(NSStringToUTF8String(self.syncState.machineOwner));

  if (self.syncState.pushNotificationsToken) {
    req->set_push_notification_token(NSStringToUTF8String(self.syncState.pushNotificationsToken));
  }

  id<SNTDaemonControlXPC> rop = [self.daemonConn synchronousRemoteObjectProxy];

  [rop databaseRuleCounts:^(struct RuleCounts counts) {
    req->set_binary_rule_count(uint32(counts.binary));
    req->set_certificate_rule_count(uint32(counts.certificate));
    req->set_compiler_rule_count(uint32(counts.compiler));
    req->set_transitive_rule_count(uint32(counts.transitive));
    req->set_teamid_rule_count(uint32(counts.teamID));
    req->set_signingid_rule_count(uint32(counts.signingID));
    req->set_cdhash_rule_count(uint32(counts.cdhash));
  }];

  [rop clientMode:^(SNTClientMode cm) {
    switch (cm) {
      case SNTClientModeMonitor: req->set_client_mode(::pbv1::MONITOR); break;
      case SNTClientModeLockdown: req->set_client_mode(::pbv1::LOCKDOWN); break;
      default: break;
    }
  }];

  __block SNTSyncType requestSyncType = SNTSyncTypeNormal;
  [rop syncTypeRequired:^(SNTSyncType syncTypeRequired) {
    requestSyncType = syncTypeRequired;
  }];

  // If user requested it or we've never had a successful sync, try from a clean slate.
  if (requestSyncType == SNTSyncTypeClean || requestSyncType == SNTSyncTypeCleanAll) {
    SLOGD(@"%@ sync requested by user",
          (requestSyncType == SNTSyncTypeCleanAll) ? @"Clean All" : @"Clean");
    req->set_request_clean_sync(true);
  }

  ::pbv1::PreflightResponse resp;
  NSError *err = [self performRequest:[self requestWithMessage:req] intoMessage:&resp timeout:30];

  if (err) {
    SLOGE(@"Failed preflight request: %@", err);
    return NO;
  }

  self.syncState.enableBundles = @(resp.enable_bundles() || resp.deprecated_bundles_enabled());
  self.syncState.enableTransitiveRules =
    @(resp.enable_transitive_rules() || resp.deprecated_enabled_transitive_whitelisting() ||
      resp.deprecated_transitive_whitelisting_enabled());
  self.syncState.enableAllEventUpload = @(resp.enable_all_event_upload());
  self.syncState.disableUnknownEventUpload = @(resp.disable_unknown_event_upload());
  self.syncState.eventBatchSize = resp.batch_size();

  // Don't let these go too low
  uint64_t value = resp.push_notification_full_sync_interval_seconds()
                     ?: resp.deprecated_fcm_full_sync_interval_seconds();
  self.syncState.pushNotificationsFullSyncInterval =
    (value < kDefaultFullSyncInterval) ? kDefaultPushNotificationsFullSyncInterval : value;

  value = resp.push_notification_global_rule_sync_deadline_seconds()
            ?: resp.deprecated_fcm_global_rule_sync_deadline_seconds();
  self.syncState.pushNotificationsGlobalRuleSyncDeadline =
    (value < kDefaultPushNotificationsGlobalRuleSyncDeadline)
      ? kDefaultPushNotificationsGlobalRuleSyncDeadline
      : value;

  // Check if our sync interval has changed
  value = resp.full_sync_interval_seconds();
  self.syncState.fullSyncInterval = (value < 60) ? kDefaultFullSyncInterval : value;

  switch (resp.client_mode()) {
    case ::pbv1::MONITOR: self.syncState.clientMode = SNTClientModeMonitor; break;
    case ::pbv1::LOCKDOWN: self.syncState.clientMode = SNTClientModeLockdown; break;
    default: break;
  }

  if (resp.has_allowed_path_regex()) {
    self.syncState.allowlistRegex = StringToNSString(resp.allowed_path_regex());
  } else if (resp.has_deprecated_whitelist_regex()) {
    self.syncState.allowlistRegex = StringToNSString(resp.deprecated_whitelist_regex());
  }

  if (resp.has_blocked_path_regex()) {
    self.syncState.blocklistRegex = StringToNSString(resp.blocked_path_regex());
  } else if (resp.has_deprecated_blacklist_regex()) {
    self.syncState.blocklistRegex = StringToNSString(resp.deprecated_blacklist_regex());
  }

  if (resp.has_block_usb_mount()) {
    self.syncState.blockUSBMount = @(resp.block_usb_mount());
  }

  self.syncState.remountUSBMode = [NSMutableArray array];
  for (const std::string &mode : resp.remount_usb_mode()) {
    [(NSMutableArray *)self.syncState.remountUSBMode addObject:StringToNSString(mode)];
  }

  if (resp.has_override_file_access_action()) {
    self.syncState.overrideFileAccessAction = StringToNSString(resp.override_file_access_action());
  }

  // Default sync type is SNTSyncTypeNormal
  //
  // Logic overview:
  // The requested sync type (clean or normal) is merely informative. The server
  // can choose to respond with a normal, clean or clean_all.
  //
  // If the server responds that it will perform a clean sync, santa will
  // treat it as either a clean or clean_all depending on which was requested.
  //
  // The server can also "override" the requested clean operation. If a normal
  // sync was requested, but the server responded that it was doing a clean or
  // clean_all sync, that will take precedence. Similarly, if only a clean sync
  // was requested, the server can force a "clean_all" operation to take place.
  self.syncState.syncType = SNTSyncTypeNormal;

  // If kSyncType response key exists, it overrides the kCleanSyncDeprecated value
  // First check if the kSyncType reponse key exists. If so, it takes precedence
  // over the kCleanSyncDeprecated key.
  std::string responseSyncType = resp.sync_type();
  if (!responseSyncType.empty()) {
    // If the client wants to Clean All, this takes precedence. The server
    // cannot override the client wanting to remove all rules.
    if (responseSyncType == "clean") {
      SLOGD(@"Clean sync requested by server");
      if (requestSyncType == SNTSyncTypeCleanAll) {
        self.syncState.syncType = SNTSyncTypeCleanAll;
      } else {
        self.syncState.syncType = SNTSyncTypeClean;
      }
    } else if (responseSyncType == "clean_all") {
      self.syncState.syncType = SNTSyncTypeCleanAll;
    }
  } else if (resp.deprecated_clean_sync()) {
    // If the deprecated key is set, the type of sync clean performed should be
    // the type that was requested. This must be set appropriately so that it
    // can be propagated during the Rule Download stage so SNTRuleTable knows
    // which rules to delete.
    SLOGD(@"Clean sync requested by server");
    if (requestSyncType == SNTSyncTypeCleanAll) {
      self.syncState.syncType = SNTSyncTypeCleanAll;
    } else {
      self.syncState.syncType = SNTSyncTypeClean;
    }
  }

  return YES;
}

@end
