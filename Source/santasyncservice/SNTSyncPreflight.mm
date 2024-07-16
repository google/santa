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

// Ignoring warning regarding deprecated declarations because of large number of
// reported issues due to checking deprecated proto fields.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

/*

Clean Sync Implementation Notes

The clean sync implementation seems a bit complex at first glance, but boils
down to the following rules:

1. If the server says to do a "CLEAN" sync, a "CLEAN" sync is performed, unless the
   client specified a "CLEAN_ALL" sync, in which case "CLEAN_ALL" is performed.
2. If the server responded that it is performing a "CLEAN_ALL" sync, a "CLEAN_ALL" is performed.
3. All other server responses result in a "NORMAL" sync.

The following table expands upon the above logic to list most of the permutations:

| Client Sync State | Clean Sync Request? | Server Response    | Sync Type Performed |
| ----------------- | ------------------- | ------------------ | ------------------- |
| NORMAL            | No                  | NORMAL OR <empty>  | NORMAL              |
| NORMAL            | No                  | CLEAN              | CLEAN               |
| NORMAL            | No                  | CLEAN_ALL          | CLEAN_ALL           |
| NORMAL            | No                  | clean_sync (dep)   | CLEAN               |
| NORMAL            | Yes                 | New AND Dep Key    | Dep key ignored     |
| CLEAN             | Yes                 | NORMAL OR <empty>  | NORMAL              |
| CLEAN             | Yes                 | CLEAN              | CLEAN               |
| CLEAN             | Yes                 | CLEAN_ALL          | CLEAN_ALL           |
| CLEAN             | Yes                 | clean_sync (dep)   | CLEAN               |
| CLEAN             | Yes                 | New AND Dep Key    | Dep key ignored     |
| CLEAN_ALL         | Yes                 | NORMAL OR <empty>  | NORMAL              |
| CLEAN_ALL         | Yes                 | CLEAN              | CLEAN_ALL           |
| CLEAN_ALL         | Yes                 | CLEAN_ALL          | CLEAN_ALL           |
| CLEAN_ALL         | Yes                 | clean_sync (dep)   | CLEAN_ALL           |
| CLEAN_ALL         | Yes                 | New AND Dep Key    | Dep key ignored     |

*/
@implementation SNTSyncPreflight

- (NSURL *)stageURL {
  NSString *stageName = [@"preflight" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  google::protobuf::Arena arena;
  auto req = google::protobuf::Arena::Create<::pbv1::PreflightRequest>(&arena);
  req->set_machine_id(NSStringToUTF8String(self.syncState.machineID));
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

  if (resp.has_enable_bundles()) {
    self.syncState.enableBundles = @(resp.enable_bundles());
  } else if (resp.has_deprecated_bundles_enabled()) {
    self.syncState.enableBundles = @(resp.deprecated_bundles_enabled());
  }

  if (resp.has_enable_transitive_rules()) {
    self.syncState.enableTransitiveRules = @(resp.enable_transitive_rules());
  } else if (resp.has_deprecated_enabled_transitive_whitelisting()) {
    self.syncState.enableTransitiveRules = @(resp.deprecated_enabled_transitive_whitelisting());
  } else if (resp.has_deprecated_transitive_whitelisting_enabled()) {
    self.syncState.enableTransitiveRules = @(resp.deprecated_transitive_whitelisting_enabled());
  }

  if (resp.has_enable_all_event_upload()) {
    self.syncState.enableAllEventUpload = @(resp.enable_all_event_upload());
  }

  if (resp.has_disable_unknown_event_upload()) {
    self.syncState.disableUnknownEventUpload = @(resp.disable_unknown_event_upload());
  }

  self.syncState.eventBatchSize = kDefaultEventBatchSize;
  if (resp.batch_size() > 0) {
    self.syncState.eventBatchSize = resp.batch_size();
  }

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

    self.syncState.remountUSBMode = [NSMutableArray array];
    for (const std::string &mode : resp.remount_usb_mode()) {
      [(NSMutableArray *)self.syncState.remountUSBMode addObject:StringToNSString(mode)];
    }
  }

  if (resp.has_override_file_access_action()) {
    switch(resp.override_file_access_action()) {
      case ::pbv1::NONE:
        self.syncState.overrideFileAccessAction = @"NONE";
        break;
      case ::pbv1::AUDIT_ONLY:
        self.syncState.overrideFileAccessAction = @"AUDIT_ONLY";
        break;
      case ::pbv1::DISABLE:
        self.syncState.overrideFileAccessAction = @"DISABLE";
        break;
      case ::pbv1::FILE_ACCESS_ACTION_UNSPECIFIED: // Intentional fallthrough
      default:
        self.syncState.overrideFileAccessAction = nil;
        break;
    }
  }

  // Default sync type is SNTSyncTypeNormal
  //
  // Logic overview:
  // The requested sync type (clean or normal) is merely informative. The server
  // can choose to respond with a NORMAL, CLEAN or CLEAN_ALL.
  //
  // If the server responds that it will perform a clean sync, santa will
  // treat it as either a clean or CLEAN_ALL depending on which was requested.
  //
  // The server can also "override" the requested clean operation. If a normal
  // sync was requested, but the server responded that it was doing a clean or
  // CLEAN_ALL sync, that will take precedence. Similarly, if only a clean sync
  // was requested, the server can force a "CLEAN_ALL" operation to take place.

  // If kSyncType response key exists, it overrides the kCleanSyncDeprecated value
  // First check if the kSyncType reponse key exists. If so, it takes precedence
  // over the kCleanSyncDeprecated key.
  if (resp.has_sync_type()) {
    switch (resp.sync_type()) {
      case ::pbv1::CLEAN:
        // If the client wants to Clean All, this takes precedence. The server
        // cannot override the client wanting to remove all rules.
        SLOGD(@"Clean sync requested by server");
        if (requestSyncType == SNTSyncTypeCleanAll) {
          self.syncState.syncType = SNTSyncTypeCleanAll;
        } else {
          self.syncState.syncType = SNTSyncTypeClean;
        }
        break;
      case ::pbv1::CLEAN_ALL:
        self.syncState.syncType = SNTSyncTypeCleanAll;
        break;
      case ::pbv1::SYNC_TYPE_UNSPECIFIED: // Intentional fallthrough
      case ::pbv1::NORMAL: // Intentional fallthrough
      default:
        self.syncState.syncType = SNTSyncTypeNormal;
        break;
    }
  } else if (resp.has_deprecated_clean_sync()) {
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
  } else {
    // Fallback if unspecified is a normal sync
    self.syncState.syncType = SNTSyncTypeNormal;
  }

  return YES;
}

@end

#pragma clang diagnostic pop
