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

#ifndef SANTA__SANTAD__DATALAYER_WATCHITEMS_H
#define SANTA__SANTAD__DATALAYER_WATCHITEMS_H

#include <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>

#include <array>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "Source/common/PrefixTree.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityEventHandler.h"

extern NSString *const kWatchItemConfigKeyVersion;
extern NSString *const kWatchItemConfigKeyWatchItems;
extern NSString *const kWatchItemConfigKeyPaths;
extern NSString *const kWatchItemConfigKeyPathsPath;
extern NSString *const kWatchItemConfigKeyPathsIsPrefix;
extern NSString *const kWatchItemConfigKeyOptions;
extern NSString *const kWatchItemConfigKeyOptionsAllowReadAccess;
extern NSString *const kWatchItemConfigKeyOptionsAuditOnly;
extern NSString *const kWatchItemConfigKeyProcesses;
extern NSString *const kWatchItemConfigKeyProcessesBinaryPath;
extern NSString *const kWatchItemConfigKeyProcessesCertificateSha256;
extern NSString *const kWatchItemConfigKeyProcessesSigningID;
extern NSString *const kWatchItemConfigKeyProcessesTeamID;
extern NSString *const kWatchItemConfigKeyProcessesCDHash;
extern NSString *const kWatchItemConfigKeyProcessesPlatformBinary;

// Forward declarations
namespace santa::santad::data_layer {
class WatchItemsPeer;
}

namespace santa::santad::data_layer {

struct WatchItemsState {
  uint64_t rule_count;
  NSString *policy_version;
  NSString *config_path;
  NSTimeInterval last_config_load_epoch;
};

class WatchItems : public std::enable_shared_from_this<WatchItems> {
 public:
  using VersionAndPolicies =
    std::pair<std::string, std::vector<std::optional<std::shared_ptr<WatchItemPolicy>>>>;
  using WatchItemsTree = santa::common::PrefixTree<std::shared_ptr<WatchItemPolicy>>;

  // Factory
  static std::shared_ptr<WatchItems> Create(NSString *config_path,
                                            uint64_t reapply_config_frequency_secs);
  // Factory
  static std::shared_ptr<WatchItems> Create(NSDictionary *config,
                                            uint64_t reapply_config_frequency_secs);

  WatchItems(NSString *config_path, dispatch_queue_t q, dispatch_source_t timer_source,
             void (^periodic_task_complete_f)(void) = nullptr);
  WatchItems(NSDictionary *config, dispatch_queue_t q, dispatch_source_t timer_source,
             void (^periodic_task_complete_f)(void) = nullptr);

  ~WatchItems();

  void BeginPeriodicTask();

  void RegisterClient(id<SNTEndpointSecurityDynamicEventHandler> client);

  void SetConfigPath(NSString *config_path);
  void SetConfig(NSDictionary *config);

  VersionAndPolicies FindPolciesForPaths(const std::vector<std::string_view> &paths);

  std::optional<WatchItemsState> State();

  friend class santa::santad::data_layer::WatchItemsPeer;

 private:
  static std::shared_ptr<WatchItems> CreateInternal(NSString *config_path, NSDictionary *config,
                                                    uint64_t reapply_config_frequency_secs);

  NSDictionary *ReadConfig();
  NSDictionary *ReadConfigLocked() ABSL_SHARED_LOCKS_REQUIRED(lock_);
  void ReloadConfig(NSDictionary *new_config);
  void UpdateCurrentState(std::unique_ptr<WatchItemsTree> new_tree,
                          std::set<std::pair<std::string, WatchItemPathType>> &&new_monitored_paths,
                          NSDictionary *new_config);
  bool BuildPolicyTree(const std::vector<std::shared_ptr<WatchItemPolicy>> &watch_items,
                       WatchItemsTree &tree,
                       std::set<std::pair<std::string, WatchItemPathType>> &paths);

  NSString *config_path_;
  NSDictionary *embedded_config_;
  dispatch_queue_t q_;
  dispatch_source_t timer_source_;
  void (^periodic_task_complete_f_)(void);

  absl::Mutex lock_;

  std::unique_ptr<WatchItemsTree> watch_items_ ABSL_GUARDED_BY(lock_);
  NSDictionary *current_config_ ABSL_GUARDED_BY(lock_);
  NSTimeInterval last_update_time_ ABSL_GUARDED_BY(lock_);
  std::set<std::pair<std::string, WatchItemPathType>> currently_monitored_paths_
    ABSL_GUARDED_BY(lock_);
  std::string policy_version_ ABSL_GUARDED_BY(lock_);
  std::set<id<SNTEndpointSecurityDynamicEventHandler>> registerd_clients_ ABSL_GUARDED_BY(lock_);
  bool periodic_task_started_ = false;
};

}  // namespace santa::santad::data_layer

#endif
