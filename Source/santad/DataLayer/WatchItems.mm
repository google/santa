/// Copyright 2022 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include "Source/santad/DataLayer/WatchItems.h"

#include <CommonCrypto/CommonDigest.h>
#include <Kernel/kern/cs_blobs.h>
#include <ctype.h>
#include <glob.h>

#include <cstddef>
#include <cstdlib>
#include <memory>
#include <optional>
#include <set>
#include <utility>

#import "Source/common/PrefixTree.h"
#import "Source/common/SNTLogging.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"

using santa::common::PrefixTree;

const NSString *kWatchItemConfigKeyVersion = @"Version";
const NSString *kWatchItemConfigKeyWatchItems = @"WatchItems";
const NSString *kWatchItemConfigKeyPath = @"Path";
const NSString *kWatchItemConfigKeyWriteOnly = @"WriteOnly";
const NSString *kWatchItemConfigKeyIsPrefix = @"IsPrefix";
const NSString *kWatchItemConfigKeyAuditOnly = @"AuditOnly";
const NSString *kWatchItemConfigKeyAllowedBinaryPaths = @"AllowedBinaryPaths";
const NSString *kWatchItemConfigKeyAllowedCertificatesSha256 = @"AllowedCertificatesSha256";
const NSString *kWatchItemConfigKeyAllowedTeamIDs = @"AllowedTeamIDs";
const NSString *kWatchItemConfigKeyAllowedCDHashes = @"AllowedCDHashes";

// Semi-arbitrary minimum allowed reapplication frequency.
// Goal is to prevent a configuration setting that would cause too much
// churn rebuilding glob paths based on the state of the filesystem.
static const uint64_t kMinReapplyConfigFrequencySecs = 15;

namespace santa::santad::data_layer {

// If the `key` exists in the `dict`, it must be of type `cls`.
// Return true if either the key does not exist, or does exist and is the correct type.
bool CheckType(const NSDictionary *dict, const NSString *key, Class cls) {
  // If the key exists, it must be of the correct type
  if (dict[key] && ![dict[key] isKindOfClass:cls]) {
    LOGE(@"Unexpected type for watch item key '%@' (got: %@, want: %@)", key,
         NSStringFromClass([dict[key] class]), NSStringFromClass(cls));

    return false;
  } else {
    return true;
  }
}

bool CheckTypeAll(const NSArray *array, const NSString *key, Class cls) {
  for (id obj : array) {
    if (![obj isKindOfClass:cls]) {
      LOGE(@"Unexpected type for watch item key '%@' (got: %@, want: %@)", key,
           NSStringFromClass([obj class]), NSStringFromClass(cls));
      return false;
    }
  }

  return true;
}

bool ConfirmValidHexString(NSString *str, size_t expected_length) {
  if (str.length != expected_length) {
    return false;
  }

  for (int i = 0; i < str.length; i++) {
    if (!isxdigit([str characterAtIndex:i])) {
      return false;
    }
  }

  return true;
}

bool ConfirmValidWatchItemConfig(const NSDictionary *watch_item_dict) {
  NSDictionary *configTypes = @{
    kWatchItemConfigKeyPath : [NSString class],
    kWatchItemConfigKeyWriteOnly : [NSNumber class],
    kWatchItemConfigKeyIsPrefix : [NSNumber class],
    kWatchItemConfigKeyAuditOnly : [NSNumber class],
    kWatchItemConfigKeyAllowedBinaryPaths : [NSArray class],
    kWatchItemConfigKeyAllowedCertificatesSha256 : [NSArray class],
    kWatchItemConfigKeyAllowedTeamIDs : [NSArray class],
    kWatchItemConfigKeyAllowedCDHashes : [NSArray class],
  };

  __block bool success = false;

  // First ensure the required keys exist
  if (!watch_item_dict[kWatchItemConfigKeyPath]) {
    LOGE(@"Missing required key '%@' for watch item", kWatchItemConfigKeyPath);
    return false;
  }

  // Ensure all keys are the expected types if they exist
  [configTypes enumerateKeysAndObjectsUsingBlock:^(NSString *key, Class cls, BOOL *stop) {
    success = CheckType(watch_item_dict, key, cls);

    // For array types, make sure all the contained objects are strings
    if (success && cls == [NSArray class]) {
      success = CheckTypeAll(watch_item_dict[key], key, [NSString class]);
    }

    // Bail early if any of the checks failed
    if (!success) {
      *stop = YES;
    }
  }];

  // Check the allowed cdhashes contain valid hex encoded data
  if (success) {
    [watch_item_dict[kWatchItemConfigKeyAllowedCDHashes]
      enumerateObjectsUsingBlock:^(NSString *obj, NSUInteger idx, BOOL *stop) {
        success = ConfirmValidHexString(obj, CS_CDHASH_LEN * 2);
        if (!success) {
          *stop = YES;
        }
      }];
  }

  // Check the allowed certificate hashes contain valid hex encoded data
  if (success) {
    [watch_item_dict[kWatchItemConfigKeyAllowedCertificatesSha256]
      enumerateObjectsUsingBlock:^(NSString *obj, NSUInteger idx, BOOL *stop) {
        success = ConfirmValidHexString(obj, CC_SHA256_DIGEST_LENGTH * 2);
        if (!success) {
          *stop = YES;
        }
      }];
  }

  return success;
}

static std::set<std::string> StringArrayToSet(NSArray<NSString *> *array) {
  std::set<std::string> strings;

  for (NSString *obj in array) {
    strings.insert(std::string([obj UTF8String]));
  }

  return strings;
}

template <uint32_t length>
static std::array<uint8_t, length> HexStringToByteArray(NSString *str) {
  std::array<uint8_t, length> bytes;

  char cur_byte[3];
  cur_byte[2] = '\0';

  for (int i = 0; i < [str length] / 2; i++) {
    cur_byte[0] = [str characterAtIndex:(i * 2)];
    cur_byte[1] = [str characterAtIndex:(i * 2 + 1)];

    bytes[i] = std::strtoul(cur_byte, nullptr, 16);
  }

  return bytes;
}

template <uint32_t length>
static std::set<std::array<uint8_t, length>> HexStringArrayToSet(NSArray<NSString *> *array) {
  std::set<std::array<uint8_t, length>> data;

  for (NSString *obj in array) {
    data.insert(HexStringToByteArray<length>(obj));
  }

  return data;
}

std::shared_ptr<WatchItems> WatchItems::Create(NSString *config_path,
                                               uint64_t reapply_config_frequency_secs) {
  if (reapply_config_frequency_secs < kMinReapplyConfigFrequencySecs) {
    LOGW(@"Invalid watch item update interval provided: %llu. Min allowed: %llu",
         reapply_config_frequency_secs, kMinReapplyConfigFrequencySecs);
    return nullptr;
  }

  dispatch_queue_t q = dispatch_queue_create("com.google.santa.daemon.watch_items.q",
                                             DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
  dispatch_source_t timer_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
  dispatch_source_set_timer(timer_source, dispatch_time(DISPATCH_TIME_NOW, 0),
                            NSEC_PER_SEC * reapply_config_frequency_secs, 0);

  return std::make_shared<WatchItems>(config_path, q, timer_source);
}

WatchItems::WatchItems(NSString *config_path, dispatch_queue_t q, dispatch_source_t timer_source,
                       void (^periodic_task_complete_f)(void))
    : config_path_(config_path),
      q_(q),
      timer_source_(timer_source),
      periodic_task_complete_f_(periodic_task_complete_f),
      watch_items_(std::make_unique<WatchItemsTree>()) {}

WatchItems::~WatchItems() {
  if (!periodic_task_started_ && timer_source_ != NULL) {
    // The timer_source_ must be resumed to ensure it has a proper retain count before being
    // destroyed. Additionally, it should first be cancelled to ensure the timer isn't ever fired
    // (see man page for `dispatch_source_cancel(3)`).
    dispatch_source_cancel(timer_source_);
    dispatch_resume(timer_source_);
  }
}

bool WatchItems::BuildPolicyTree(const std::vector<std::shared_ptr<WatchItemPolicy>> &watch_items,
                                 PrefixTree<std::shared_ptr<WatchItemPolicy>> &tree,
                                 std::set<std::string> &paths) {
  glob_t *g = (glob_t *)alloca(sizeof(glob_t));
  for (const std::shared_ptr<WatchItemPolicy> &item : watch_items) {
    int err = glob(item->path.c_str(), 0, nullptr, g);
    if (err != 0 && err != GLOB_NOMATCH) {
      LOGE(@"Failed to generate path names for watch item: %s", item->name.c_str());
      return false;
    }

    for (size_t i = g->gl_offs; i < g->gl_pathc; i++) {
      if (item->path_type == WatchItemPathType::kPrefix) {
        tree.InsertPrefix(g->gl_pathv[i], item);
      } else {
        tree.InsertLiteral(g->gl_pathv[i], item);
      }

      paths.insert(g->gl_pathv[i]);
    }
    globfree(g);
  }

  return true;
}

void WatchItems::RegisterClient(id<SNTEndpointSecurityDynamicEventHandler> client) {
  absl::MutexLock lock(&lock_);
  registerd_clients_.insert(client);
}

bool WatchItems::ParseConfig(NSDictionary *config,
                             std::vector<std::shared_ptr<WatchItemPolicy>> &policies) {
  bool config_ok = true;

  if (![config[kWatchItemConfigKeyVersion] isKindOfClass:[NSString class]]) {
    LOGE(@"Missing top level string key '%@'", kWatchItemConfigKeyVersion);
  }

  id watch_items = config[kWatchItemConfigKeyWatchItems];

  if (![watch_items isKindOfClass:[NSDictionary class]]) {
    LOGE(@"Missing top level dictionary key '%@'", kWatchItemConfigKeyWatchItems);
    return false;
  }

  for (id key in watch_items) {
    if (![key isKindOfClass:[NSString class]]) {
      LOGE(@"Invalid key %@ (class: %@)", key, NSStringFromClass([key class]));
      config_ok = false;
      break;
    }

    if (![watch_items[key] isKindOfClass:[NSDictionary class]]) {
      LOGE(@"Config for '%@' must be a dictionary (got: %@), skipping", key,
           NSStringFromClass([watch_items[key] class]));
      config_ok = false;
      break;
    }

    NSDictionary *watch_item = watch_items[key];

    if (!ConfirmValidWatchItemConfig(watch_item)) {
      LOGE(@"Invalid config for watch item: '%@'", key);
      config_ok = false;
      break;
    }

    policies.push_back(std::make_shared<WatchItemPolicy>(
      [key UTF8String], [watch_item[kWatchItemConfigKeyPath] UTF8String],
      [(watch_item[kWatchItemConfigKeyWriteOnly] ?: @(0)) boolValue],
      ([(watch_item[kWatchItemConfigKeyIsPrefix] ?: @(0)) boolValue] == NO)
        ? WatchItemPathType::kLiteral
        : WatchItemPathType::kPrefix,
      [(watch_item[kWatchItemConfigKeyAuditOnly] ?: @(1)) boolValue],
      StringArrayToSet(watch_item[kWatchItemConfigKeyAllowedBinaryPaths]),
      StringArrayToSet(watch_item[kWatchItemConfigKeyAllowedTeamIDs]),
      HexStringArrayToSet<CS_CDHASH_LEN>(watch_item[kWatchItemConfigKeyAllowedCDHashes]),
      StringArrayToSet(watch_item[kWatchItemConfigKeyAllowedCertificatesSha256])));
  }

  return config_ok;
}

void WatchItems::UpdateCurrentState(
  std::unique_ptr<PrefixTree<std::shared_ptr<WatchItemPolicy>>> new_tree,
  std::set<std::string> &&new_monitored_paths, NSDictionary *new_config) {
  absl::MutexLock lock(&lock_);

  // The following conditions require updating the current config:
  // 1. The current config doesn't exist but the new one does
  // 2. The current config exists but the new one doesn't
  // 3. The set of monitored paths changed
  // 4. The configuration changed
  if ((current_config_ != nil && new_config == nil) ||
      (current_config_ == nil && new_config != nil) ||
      (currently_monitored_paths_ != new_monitored_paths) ||
      (new_config && ![current_config_ isEqualToDictionary:new_config])) {
    // TODO(mlw): In upcoming PR, need to use ES API to stop watching removed paths,
    // and start watching newly configured paths.

    std::swap(watch_items_, new_tree);
    std::swap(currently_monitored_paths_, new_monitored_paths);
    current_config_ = new_config;
    if (new_config) {
      policy_version_ = [new_config[kWatchItemConfigKeyVersion] UTF8String];
    } else {
      policy_version_ = "";
    }

    bool anyPathsMonitored = currently_monitored_paths_.size() > 0;
    for (const id<SNTEndpointSecurityDynamicEventHandler> &client : registerd_clients_) {
      // Note: Enable clients on an async queue in case they perform any
      // synchronous work that could trigger ES events. Otherwise they might
      // trigger AUTH ES events that would attempt to re-enter this object and
      // potentially deadlock.
      dispatch_async(q_, ^{
        if (anyPathsMonitored) {
          [client enable];
        } else {
          [client disable];
        }
      });
    }
  } else {
    LOGD(@"No changes to set of watched paths.");
  }
}

void WatchItems::ReloadConfig(NSDictionary *new_config) {
  std::vector<std::shared_ptr<WatchItemPolicy>> new_policies;
  auto new_tree = std::make_unique<PrefixTree<std::shared_ptr<WatchItemPolicy>>>();
  std::set<std::string> new_monitored_paths;

  if (new_config) {
    if (!ParseConfig(new_config, new_policies)) {
      LOGE(@"Failed to apply new filesystem monitoring config");
      return;
    }

    if (!BuildPolicyTree(new_policies, *new_tree, new_monitored_paths)) {
      LOGE(@"Failed to build new filesystem monitoring policy");
      return;
    }
  }

  UpdateCurrentState(std::move(new_tree), std::move(new_monitored_paths), new_config);
}

NSDictionary *WatchItems::ReadConfig() {
  absl::ReaderMutexLock lock(&lock_);
  return ReadConfigLocked();
}

NSDictionary *WatchItems::ReadConfigLocked() {
  if (config_path_) {
    return [NSDictionary dictionaryWithContentsOfFile:config_path_];
  } else {
    return nil;
  }
}

void WatchItems::BeginPeriodicTask() {
  if (periodic_task_started_) {
    return;
  }

  std::weak_ptr<WatchItems> weak_watcher = weak_from_this();
  dispatch_source_set_event_handler(timer_source_, ^{
    std::shared_ptr<WatchItems> shared_watcher = weak_watcher.lock();
    if (!shared_watcher) {
      return;
    }

    shared_watcher->ReloadConfig(shared_watcher->ReadConfig());

    if (shared_watcher->periodic_task_complete_f_) {
      shared_watcher->periodic_task_complete_f_();
    }
  });

  dispatch_resume(timer_source_);
  periodic_task_started_ = true;
}

std::string WatchItems::PolicyVersion() {
  absl::ReaderMutexLock lock(&lock_);
  return policy_version_;
}

std::optional<std::shared_ptr<WatchItemPolicy>> WatchItems::FindPolicyForPath(const char *input) {
  if (!input) {
    return std::nullopt;
  }

  absl::ReaderMutexLock lock(&lock_);
  return watch_items_->LookupLongestMatchingPrefix(input);
}

void WatchItems::SetConfigPath(NSString *config_path) {
  // Acquire the lock to set the config path and read the config, but drop
  // the lock before reloading the config
  NSDictionary *config;
  {
    absl::MutexLock lock(&lock_);
    config_path_ = config_path;
    config = ReadConfigLocked();
  }
  ReloadConfig(config);
}

}  // namespace santa::santad::data_layer
