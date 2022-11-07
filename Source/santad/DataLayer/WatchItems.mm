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

#include <memory>

#import "Source/common/SNTLogging.h"

static const NSString *kWatchItemConfigKeyPath = @"Path";
static const NSString *kWatchItemConfigKeyWriteOnly = @"WriteOnly";
static const NSString *kWatchItemConfigKeyIsPrefix = @"IsPrefix";
static const NSString *kWatchItemConfigKeyAuditOnly = @"AuditOnly";
static const NSString *kWatchItemConfigKeyAllowedBinaryPaths = @"AllowedBinaryPaths";
static const NSString *kWatchItemConfigKeyAllowedCertificatesSha256 = @"AllowedCertificatesSha256";
static const NSString *kWatchItemConfigKeyAllowedTeamIDs = @"AllowedTeamIDs";
static const NSString *kWatchItemConfigKeyAllowedCDHashes = @"AllowedCDHashes";

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

  return success;
}

std::vector<std::string> ConfigArrayToVector(NSArray *array) {
  std::vector<std::string> vec;
  vec.reserve([array count]);

  for (NSString *obj in array) {
    vec.push_back(std::string([obj UTF8String]));
  }
  return vec;
}

WatchItem::WatchItem(std::string n, std::string p, bool wo, bool ip, bool ao,
                     std::vector<std::string> &&abp, std::vector<std::string> &&acs,
                     std::vector<std::string> &&ati, std::vector<std::string> &&ach)
    : name(n),
      path(p),
      write_only(wo),
      is_prefix(ip),
      audit_only(ao),
      allowed_binary_paths(std::move(abp)),
      allowed_certificates_sha256(std::move(acs)),
      allowed_team_ids(std::move(ati)),
      allowed_cdhashes(std::move(ach)) {}

std::unique_ptr<WatchItems> WatchItems::Create(NSString *config_path,
                                               uint64_t reapply_config_frequency_secs) {
  if (!config_path) {
    return nullptr;
  }

  dispatch_queue_t q = dispatch_queue_create("com.google.santa.daemon.watch_items.q",
                                             DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
  dispatch_source_t timer_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
  dispatch_source_set_timer(timer_source, dispatch_time(DISPATCH_TIME_NOW, 0),
                            NSEC_PER_SEC * reapply_config_frequency_secs, 0);

  return std::make_unique<WatchItems>(config_path, timer_source);
}

WatchItems::WatchItems(NSString *config_path, dispatch_source_t timer_source)
    : config_path_(config_path), timer_source_(timer_source) {}

void WatchItems::ReloadConfig() {
  NSDictionary *new_config = [NSDictionary dictionaryWithContentsOfFile:config_path_];

  if ([new_config isEqualToDictionary:current_config_]) {
    // Config wasn't updated, nothing to do
    return;
  }

  LOGI(@"File system monitoring config changed. Applying new settings.");

  std::vector<std::shared_ptr<WatchItem>> new_watch_items;

  for (id key in new_config) {
    if (![key isKindOfClass:[NSString class]]) {
      LOGE(@"In valid key %@ (class: %@), skipping", key, NSStringFromClass([key class]));
      continue;
    }

    if (![new_config[key] isKindOfClass:[NSDictionary class]]) {
      LOGE(@"Config for '%@' must be a dictionary (got: %@), skipping", key,
           NSStringFromClass([new_config[key] class]));
      continue;
    }

    NSDictionary *watch_item = new_config[key];

    if (!ConfirmValidWatchItemConfig(watch_item)) {
      LOGE(@"Invalid config for watch item: '%@', skipping", key);
      continue;
    }

    new_watch_items.push_back(std::make_shared<WatchItem>(
      [key UTF8String], [watch_item[kWatchItemConfigKeyPath] UTF8String],
      [(watch_item[kWatchItemConfigKeyWriteOnly] ?: @(0)) boolValue],
      [(watch_item[kWatchItemConfigKeyIsPrefix] ?: @(0)) boolValue],
      [(watch_item[kWatchItemConfigKeyAuditOnly] ?: @(1)) boolValue],
      ConfigArrayToVector(watch_item[kWatchItemConfigKeyAllowedBinaryPaths]),
      ConfigArrayToVector(watch_item[kWatchItemConfigKeyAllowedCertificatesSha256]),
      ConfigArrayToVector(watch_item[kWatchItemConfigKeyAllowedTeamIDs]),
      ConfigArrayToVector(watch_item[kWatchItemConfigKeyAllowedCDHashes])));
  }

  current_config_ = new_config;
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

    shared_watcher->ReloadConfig();
  });
}

}  // namespace santa::santad::data_layer
