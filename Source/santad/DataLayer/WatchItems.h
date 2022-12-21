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

extern const NSString *kWatchItemConfigKeyPath;
extern const NSString *kWatchItemConfigKeyWriteOnly;
extern const NSString *kWatchItemConfigKeyIsPrefix;
extern const NSString *kWatchItemConfigKeyAuditOnly;
extern const NSString *kWatchItemConfigKeyAllowedBinaryPaths;
extern const NSString *kWatchItemConfigKeyAllowedCertificatesSha256;
extern const NSString *kWatchItemConfigKeyAllowedTeamIDs;
extern const NSString *kWatchItemConfigKeyAllowedCDHashes;

// Forward declarations
namespace santa::santad::data_layer {
class WatchItemsPeer;
}

namespace santa::santad::data_layer {

class WatchItems : public std::enable_shared_from_this<WatchItems> {
 public:
  using VersionAndPolicies =
    std::pair<std::string, std::vector<std::optional<std::shared_ptr<WatchItemPolicy>>>>;
  using WatchItemsTree = santa::common::PrefixTree<std::shared_ptr<WatchItemPolicy>>;

  // Factory
  static std::shared_ptr<WatchItems> Create(NSString *config_path,
                                            uint64_t reapply_config_frequency_secs);

  WatchItems(NSString *config_path_, dispatch_queue_t q, dispatch_source_t timer_source,
             void (^periodic_task_complete_f)(void) = nullptr);
  ~WatchItems();

  void BeginPeriodicTask();

  void RegisterClient(id<SNTEndpointSecurityDynamicEventHandler> client);

  void SetConfigPath(NSString *config_path);
  VersionAndPolicies FindPolciesForPaths(const std::vector<std::string> &paths);
  std::string PolicyVersion();

  friend class santa::santad::data_layer::WatchItemsPeer;

 private:
  NSDictionary *ReadConfig();
  NSDictionary *ReadConfigLocked() ABSL_SHARED_LOCKS_REQUIRED(lock_);
  void ReloadConfig(NSDictionary *new_config);
  void UpdateCurrentState(std::unique_ptr<WatchItemsTree> new_tree,
                          std::set<std::pair<std::string, WatchItemPathType>> &&new_monitored_paths,
                          NSDictionary *new_config);
  bool ParseConfig(NSDictionary *config, std::vector<std::shared_ptr<WatchItemPolicy>> &policies);
  bool BuildPolicyTree(const std::vector<std::shared_ptr<WatchItemPolicy>> &watch_items,
                       WatchItemsTree &tree,
                       std::set<std::pair<std::string, WatchItemPathType>> &paths);

  NSString *config_path_;
  dispatch_queue_t q_;
  dispatch_source_t timer_source_;
  void (^periodic_task_complete_f_)(void);

  absl::Mutex lock_;

  std::unique_ptr<WatchItemsTree> watch_items_ ABSL_GUARDED_BY(lock_);
  NSDictionary *current_config_ ABSL_GUARDED_BY(lock_);
  std::set<std::pair<std::string, WatchItemPathType>> currently_monitored_paths_
    ABSL_GUARDED_BY(lock_);
  std::string policy_version_ ABSL_GUARDED_BY(lock_);
  std::set<id<SNTEndpointSecurityDynamicEventHandler>> registerd_clients_ ABSL_GUARDED_BY(lock_);
  bool periodic_task_started_ = false;
};

}  // namespace santa::santad::data_layer

#endif
