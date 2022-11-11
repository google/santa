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

#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <utility>

#include <memory>
#include <set>
#include <string>
#include <vector>

#include "Source/common/PrefixTree.h"

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

struct WatchItemPolicy {
  WatchItemPolicy(std::string n, std::string p, bool wo = false, bool ip = false, bool ao = true,
                  std::vector<std::string> &&abp = {}, std::vector<std::string> &&acs = {},
                  std::vector<std::string> &&ati = {}, std::vector<std::string> &&ach = {});

  std::string name;
  std::string path;
  bool write_only;
  bool is_prefix;
  bool audit_only;
  std::vector<std::string> allowed_binary_paths;
  std::vector<std::string> allowed_certificates_sha256;
  std::vector<std::string> allowed_team_ids;
  std::vector<std::string> allowed_cdhashes;
};

struct WatchItem {
  WatchItem(std::string p, bool ip);

  std::string path;
  bool is_prefix;

  bool operator<(const WatchItem &wi) const;
  bool operator==(const WatchItem &wi) const;
  friend std::ostream &operator<<(std::ostream &os, const WatchItem &wi);
};

class WatchItems : public std::enable_shared_from_this<WatchItems> {
 public:
  std::unique_ptr<WatchItems> Create(NSString *config_path, uint64_t reapply_config_frequency_secs);
  WatchItems(NSString *config_path_, dispatch_source_t timer_source);

  void BeginPeriodicTask();

  std::optional<std::shared_ptr<WatchItemPolicy>> FindPolicyForPath(const char *input);

  friend class santa::santad::data_layer::WatchItemsPeer;

 private:
  void ReloadConfig(NSDictionary *new_config);
  bool SetCurrentConfig(
    std::unique_ptr<santa::common::PrefixTree<std::shared_ptr<WatchItemPolicy>>> new_tree,
    std::set<WatchItem> &&new_monitored_paths);
  bool ParseConfig(NSDictionary *config, std::vector<std::shared_ptr<WatchItemPolicy>> &policies);
  bool BuildPolicyTree(const std::vector<std::shared_ptr<WatchItemPolicy>> &watch_items,
                       santa::common::PrefixTree<std::shared_ptr<WatchItemPolicy>> &tree,
                       std::set<WatchItem> &paths);

  NSString *config_path_;
  dispatch_source_t timer_source_;
  std::unique_ptr<santa::common::PrefixTree<std::shared_ptr<WatchItemPolicy>>> watch_items_;
  std::set<WatchItem> currently_monitored_paths_;
  absl::Mutex lock_;
  bool periodic_task_started_ = false;
};

}  // namespace santa::santad::data_layer

#endif
