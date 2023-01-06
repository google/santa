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
#include <sys/syslimits.h>

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#import "Source/common/PrefixTree.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/Unit.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
using santa::common::PrefixTree;
using santa::common::Unit;
using santa::santad::data_layer::WatchItemPathType;
using santa::santad::data_layer::WatchItemPolicy;

// Type aliases
using ValidatorBlock = bool (^)(id, NSError **);
using PathAndTypePair = std::pair<std::string, WatchItemPathType>;
using PathList = std::vector<PathAndTypePair>;
using ProcessList = std::vector<WatchItemPolicy::Process>;

NSString *const kWatchItemConfigKeyVersion = @"Version";
NSString *const kWatchItemConfigKeyWatchItems = @"WatchItems";
NSString *const kWatchItemConfigKeyPaths = @"Paths";
NSString *const kWatchItemConfigKeyPathsPath = @"Path";
NSString *const kWatchItemConfigKeyPathsIsPrefix = @"IsPrefix";
NSString *const kWatchItemConfigKeyOptions = @"Options";
NSString *const kWatchItemConfigKeyOptionsAllowReadAccess = @"AllowReadAccess";
NSString *const kWatchItemConfigKeyOptionsAuditOnly = @"AuditOnly";
NSString *const kWatchItemConfigKeyProcesses = @"Processes";
NSString *const kWatchItemConfigKeyProcessesBinaryPath = @"BinaryPath";
NSString *const kWatchItemConfigKeyProcessesCertificateSha256 = @"CertificateSha256";
NSString *const kWatchItemConfigKeyProcessesTeamID = @"TeamID";
NSString *const kWatchItemConfigKeyProcessesCDHash = @"CDHash";

// https://developer.apple.com/help/account/manage-your-team/locate-your-team-id/
static constexpr NSUInteger kMaxTeamIDLength = 10;

// Semi-arbitrary minimum allowed reapplication frequency.
// Goal is to prevent a configuration setting that would cause too much
// churn rebuilding glob paths based on the state of the filesystem.
static constexpr uint64_t kMinReapplyConfigFrequencySecs = 15;

namespace santa::santad::data_layer {

/// Ensure the given string has the expected length and only
/// contains valid hex digits
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

static std::vector<uint8_t> HexStringToBytes(NSString *str) {
  if (!str) {
    return std::vector<uint8_t>{};
  }

  std::vector<uint8_t> bytes;
  bytes.reserve(str.length / 2);

  char cur_byte[3];
  cur_byte[2] = '\0';

  for (int i = 0; i < [str length] / 2; i++) {
    cur_byte[0] = [str characterAtIndex:(i * 2)];
    cur_byte[1] = [str characterAtIndex:(i * 2 + 1)];

    bytes.push_back(std::strtoul(cur_byte, nullptr, 16));
  }

  return bytes;
}

// Given a length, returns a ValidatorBlock that confirms the
// string is a valid hex string of the given length.
ValidatorBlock HexValidator(NSUInteger expected_length) {
  return ^bool(NSString *val, NSError **err) {
    if (!ConfirmValidHexString(val, expected_length)) {
      if (err) {
        NSString *err_str =
          [NSString stringWithFormat:@"Expected hex string of length %lu", expected_length];
        *err = [NSError errorWithDomain:@"com.google.santa.watchitems"
                                   code:100
                               userInfo:@{NSLocalizedDescriptionKey : err_str}];
      }
      return false;
    }

    return true;
  };
}

// Given a max length, returns a ValidatorBlock that confirms the
// string is a not longer than the max.
ValidatorBlock MaxLenValidator(NSUInteger max_length) {
  return ^bool(NSString *val, NSError **err) {
    if (val.length > max_length) {
      if (err) {
        NSString *err_str =
          [NSString stringWithFormat:@"Value too long. Got: %lu, Max: %lu", val.length, max_length];
        *err = [NSError errorWithDomain:@"com.google.santa.watchitems"
                                   code:101
                               userInfo:@{NSLocalizedDescriptionKey : err_str}];
      }
      return false;
    }

    return true;
  };
}

/// Ensure the key exists (if required) and the value matches the expected type
bool VerifyConfigKey(NSString *name, NSDictionary *dict, const NSString *key, Class expected,
                     bool required = false, bool (^Validator)(id, NSError **) = nil) {
  if (dict[key]) {
    if (![dict[key] isKindOfClass:expected]) {
      LOGE(@"In watch item '%@': Expected type '%@' for key '%@' (got: %@)", name,
           NSStringFromClass(expected), key, NSStringFromClass([dict[key] class]));
      return false;
    }

    NSError *err;
    if (Validator && !Validator(dict[key], &err)) {
      LOGE(@"In watch item '%@': Invalid content in key '%@': %@", name, key,
           err.localizedDescription);
      return false;
    }
  } else if (required) {
    LOGE(@"In watch item '%@': Missing required key '%@'", name, key);
    return false;
  }

  return true;
}

/// Ensure all values of the array key in the dictionary conform to the
/// expected type. If a Validator block is supplied, each item is also
/// subject to the custom validation method.
bool VerifyConfigKeyArray(NSString *name, NSDictionary *dict, NSString *key, Class expected,
                          bool (^Validator)(id, NSError **) = nil) {
  if (!VerifyConfigKey(name, dict, key, [NSArray class])) {
    return false;
  }

  __block bool success = true;

  [dict[key] enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
    if (![obj isKindOfClass:expected]) {
      success = false;
      LOGE(@"In watch item '%@': Expected all '%@' types in array key '%@'", name,
           NSStringFromClass(expected), key);
      *stop = YES;
      return;
    }

    NSError *err;
    if (Validator && !Validator(obj, &err)) {
      LOGE(@"In watch item '%@': Invalid content in array key '%@': %@", name, key,
           err.localizedDescription);
      success = false;
      *stop = YES;
      return;
    }
  }];

  return success;
}

/// The `Paths` array can contain only `string` and `dict` types:
/// - For `string` types, the default path type `kDefaultPathType` is used
/// - For `dict` types, there is a required `Path` key. and an optional
///   `IsPrefix` key to set the path type to something other than the default
///
/// Example:
/// <array>
///   <string>/my/path</string>
///   <dict>
///     <key>Path</key>
///     <string>/another/partial/path</string>
///     <key>IsPrefix</key>
///     <true/>
///   </dict>
/// </array>
std::variant<Unit, PathList> VerifyConfigWatchItemPaths(NSString *name, NSArray<id> *paths) {
  PathList path_list;

  for (id path in paths) {
    if ([path isKindOfClass:[NSDictionary class]]) {
      NSDictionary *path_dict = (NSDictionary *)path;
      if (!VerifyConfigKey(name, path_dict, kWatchItemConfigKeyPathsPath, [NSString class], true,
                           MaxLenValidator(PATH_MAX))) {
        return Unit{};
      }

      NSString *path_str = path_dict[kWatchItemConfigKeyPathsPath];
      WatchItemPathType path_type = kWatchItemPolicyDefaultPathType;

      if (VerifyConfigKey(name, path_dict, kWatchItemConfigKeyPathsIsPrefix, [NSNumber class])) {
        path_type = ([(NSNumber *)path_dict[kWatchItemConfigKeyPathsIsPrefix] boolValue] == NO
                       ? WatchItemPathType::kLiteral
                       : WatchItemPathType::kPrefix);
      } else {
        return Unit{};
      }

      path_list.push_back({std::string(path_str.UTF8String, path_str.length), path_type});
    } else if ([path isKindOfClass:[NSString class]]) {
      if (((NSString *)path).length > PATH_MAX) {
        LOGE(@"In watch item '%@': Provided path length (%zu) exceed max allowed length (%d)", name,
             ((NSString *)path).length, PATH_MAX);
        return Unit{};
      }
      path_list.push_back({std::string(((NSString *)path).UTF8String, ((NSString *)path).length),
                           kWatchItemPolicyDefaultPathType});
    } else {
      LOGE(@"In watch item '%@': %@ array item with invalid type. Expected 'dict' or 'string' "
           @"(got: %@)",
           name, kWatchItemConfigKeyPaths, NSStringFromClass([path class]));
      return Unit{};
    }
  }

  if (path_list.size() == 0) {
    LOGE(@"In watch item '%@': No paths specified", name);
    return Unit{};
  }

  return path_list;
}

/// The `Processes` array can only contain dictionaries. Each dictionary can
/// contain the attributes that describe a single process.
///
/// <array>
///   <dict>
///     <key>BinaryPaths</key>
///     <string>AAAA</string>
///     <key>TeamIDs</key>
///     <string>BBBB</string>
///   </dict>
///   <dict>
///     <key>CertificatesSha256</key>
///     <string>CCCC</string>
///     <key>CDHashes</key>
///     <string>DDDD</string>
///   </dict>
/// </array>
std::variant<Unit, ProcessList> VerifyConfigWatchItemProcesses(NSString *name,
                                                               NSDictionary *watch_item) {
  __block ProcessList proc_list;

  if (!VerifyConfigKeyArray(
        name, watch_item, kWatchItemConfigKeyProcesses, [NSDictionary class],
        ^bool(NSDictionary *process, NSError **err) {
          if (!VerifyConfigKey(name, process, kWatchItemConfigKeyProcessesBinaryPath,
                               [NSString class], false, MaxLenValidator(PATH_MAX)) ||
              !VerifyConfigKey(name, process, kWatchItemConfigKeyProcessesTeamID, [NSString class],
                               false, MaxLenValidator(kMaxTeamIDLength)) ||
              !VerifyConfigKey(name, process, kWatchItemConfigKeyProcessesCDHash, [NSString class],
                               false, HexValidator(CS_CDHASH_LEN * 2)) ||
              !VerifyConfigKey(name, process, kWatchItemConfigKeyProcessesCertificateSha256,
                               [NSString class], false,
                               HexValidator(CC_SHA256_DIGEST_LENGTH * 2))) {
            if (err) {
              *err = [NSError
                errorWithDomain:@"com.google.santa.watchitems"
                           code:101
                       userInfo:@{NSLocalizedDescriptionKey : @"Failed to verify key content"}];
            }
            return false;
          }

          // Ensure at least one attribute set
          if (!process[kWatchItemConfigKeyProcessesBinaryPath] &&
              !process[kWatchItemConfigKeyProcessesTeamID] &&
              !process[kWatchItemConfigKeyProcessesCDHash] &&
              !process[kWatchItemConfigKeyProcessesCertificateSha256]) {
            if (err) {
              *err = [NSError errorWithDomain:@"com.google.santa.watchitems"
                                         code:101
                                     userInfo:@{
                                       NSLocalizedDescriptionKey :
                                         @"No valid attributes set in process dictionary"
                                     }];
            }
            return false;
          }

          proc_list.push_back(WatchItemPolicy::Process(
            std::string([(process[kWatchItemConfigKeyProcessesBinaryPath] ?: @"") UTF8String]),
            std::string([(process[kWatchItemConfigKeyProcessesTeamID] ?: @"") UTF8String]),
            HexStringToBytes(process[kWatchItemConfigKeyProcessesCDHash]),
            std::string(
              [(process[kWatchItemConfigKeyProcessesCertificateSha256] ?: @"") UTF8String])));

          return true;
        })) {
    return Unit{};
  }

  return proc_list;
}

/// Ensure that a given watch item conforms to expected structure
///
/// Example:
/// <dict>
///   <key>Paths</key>
///   <array>
///   ... See VerifyConfigWatchItemPaths for more details ...
///   </array>
///   <key>Options</key>
///   <dict>
///     <key>AllowReadAccess</key>
///     <false/>
///     <key>AuditOnly</key>
///     <false/>
///   </dict>
///   <key>Processes</key>
///   <array>
///   ... See VerifyConfigWatchItemProcesses for more details ...
///   </array>
/// </dict>
bool ParseConfigSingleWatchItem(NSString *name, NSDictionary *watch_item,
                                std::vector<std::shared_ptr<WatchItemPolicy>> &policies) {
  if (!VerifyConfigKey(name, watch_item, kWatchItemConfigKeyPaths, [NSArray class], true)) {
    return false;
  }

  std::variant<Unit, PathList> path_list =
    VerifyConfigWatchItemPaths(name, watch_item[kWatchItemConfigKeyPaths]);

  if (std::holds_alternative<Unit>(path_list)) {
    return false;
  }

  if (!VerifyConfigKey(name, watch_item, kWatchItemConfigKeyOptions, [NSDictionary class])) {
    return false;
  }

  NSDictionary *options = watch_item[kWatchItemConfigKeyOptions];
  if (options) {
    if (!VerifyConfigKey(name, options, kWatchItemConfigKeyOptionsAllowReadAccess,
                         [NSNumber class])) {
      return false;
    }

    if (!VerifyConfigKey(name, options, kWatchItemConfigKeyOptionsAuditOnly, [NSNumber class])) {
      return false;
    }
  }

  bool allow_read_access = options[kWatchItemConfigKeyOptionsAllowReadAccess]
                             ? [options[kWatchItemConfigKeyOptionsAllowReadAccess] booleanValue]
                             : kWatchItemPolicyDefaultAllowReadAccess;
  bool audit_only = options[kWatchItemConfigKeyOptionsAuditOnly]
                      ? [options[kWatchItemConfigKeyOptionsAuditOnly] booleanValue]
                      : kWatchItemPolicyDefaultAuditOnly;

  std::variant<Unit, ProcessList> proc_list = VerifyConfigWatchItemProcesses(name, watch_item);
  if (std::holds_alternative<Unit>(proc_list)) {
    return false;
  }

  for (const PathAndTypePair &path_type_pair : std::get<PathList>(path_list)) {
    policies.push_back(std::make_shared<WatchItemPolicy>(
      [name UTF8String], path_type_pair.first, path_type_pair.second, allow_read_access, audit_only,
      std::get<ProcessList>(proc_list)));
  }

  return true;
}

bool ParseConfig(NSDictionary *config, std::vector<std::shared_ptr<WatchItemPolicy>> &policies) {
  if (![config[kWatchItemConfigKeyVersion] isKindOfClass:[NSString class]]) {
    LOGE(@"Missing top level string key '%@'", kWatchItemConfigKeyVersion);
    return false;
  }

  if (config[kWatchItemConfigKeyWatchItems] &&
      ![config[kWatchItemConfigKeyWatchItems] isKindOfClass:[NSDictionary class]]) {
    LOGE(@"Top level key '%@' must be a dictionary", kWatchItemConfigKeyWatchItems);
    return false;
  }

  NSDictionary *watch_items = config[kWatchItemConfigKeyWatchItems];

  for (id key in watch_items) {
    if (![key isKindOfClass:[NSString class]]) {
      LOGE(@"Invalid WatchItems key %@: Expected type '%@' (got: %@)", key,
           NSStringFromClass([NSString class]), NSStringFromClass([key class]));
      return false;
    }

    if (![watch_items[key] isKindOfClass:[NSDictionary class]]) {
      LOGE(@"Config for '%@' must be a dictionary (got: %@)", key,
           NSStringFromClass([watch_items[key] class]));
      return false;
    }

    if (!ParseConfigSingleWatchItem(key, watch_items[key], policies)) {
      return false;
    }
  }

  return true;
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
                                 std::set<std::pair<std::string, WatchItemPathType>> &paths) {
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

      paths.insert({g->gl_pathv[i], item->path_type});
    }
    globfree(g);
  }

  return true;
}

void WatchItems::RegisterClient(id<SNTEndpointSecurityDynamicEventHandler> client) {
  absl::MutexLock lock(&lock_);
  registerd_clients_.insert(client);
}

void WatchItems::UpdateCurrentState(
  std::unique_ptr<PrefixTree<std::shared_ptr<WatchItemPolicy>>> new_tree,
  std::set<std::pair<std::string, WatchItemPathType>> &&new_monitored_paths,
  NSDictionary *new_config) {
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
    std::vector<std::pair<std::string, WatchItemPathType>> paths_to_watch;
    std::vector<std::pair<std::string, WatchItemPathType>> paths_to_stop_watching;

    // New paths to watch are those that are in the new set, but not current
    std::set_difference(new_monitored_paths.begin(), new_monitored_paths.end(),
                        currently_monitored_paths_.begin(), currently_monitored_paths_.end(),
                        std::back_inserter(paths_to_watch));

    // Paths to stop watching are in the current set, but not new
    std::set_difference(currently_monitored_paths_.begin(), currently_monitored_paths_.end(),
                        new_monitored_paths.begin(), new_monitored_paths.end(),
                        std::back_inserter(paths_to_stop_watching));

    std::swap(watch_items_, new_tree);
    std::swap(currently_monitored_paths_, new_monitored_paths);
    current_config_ = new_config;
    if (new_config) {
      policy_version_ = [new_config[kWatchItemConfigKeyVersion] UTF8String];
    } else {
      policy_version_ = "";
    }

    for (const id<SNTEndpointSecurityDynamicEventHandler> &client : registerd_clients_) {
      // Note: Enable clients on an async queue in case they perform any
      // synchronous work that could trigger ES events. Otherwise they might
      // trigger AUTH ES events that would attempt to re-enter this object and
      // potentially deadlock.
      dispatch_async(q_, ^{
        [client watchItemsCount:currently_monitored_paths_.size()
                       newPaths:paths_to_watch
                   removedPaths:paths_to_stop_watching];
      });
    }
  } else {
    LOGD(@"No changes to set of watched paths.");
  }
}

void WatchItems::ReloadConfig(NSDictionary *new_config) {
  std::vector<std::shared_ptr<WatchItemPolicy>> new_policies;
  auto new_tree = std::make_unique<PrefixTree<std::shared_ptr<WatchItemPolicy>>>();
  std::set<std::pair<std::string, WatchItemPathType>> new_monitored_paths;

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

WatchItems::VersionAndPolicies WatchItems::FindPolciesForPaths(
  const std::vector<std::string_view> &paths) {
  absl::ReaderMutexLock lock(&lock_);
  std::vector<std::optional<std::shared_ptr<WatchItemPolicy>>> policies;

  for (const auto &path : paths) {
    policies.push_back(watch_items_->LookupLongestMatchingPrefix(path.data()));
  }

  return {policy_version_, policies};
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
