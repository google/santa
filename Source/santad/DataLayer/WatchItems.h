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

#include <memory>
#include <string>
#include <vector>

#include "Source/common/PrefixTree.h"

namespace santa::santad::data_layer {
struct WatchItem {
  WatchItem(std::string n, std::string p, bool wo, bool ip, bool ao, std::vector<std::string> &&abp,
            std::vector<std::string> &&acs, std::vector<std::string> &&ati,
            std::vector<std::string> &&ach);
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

class WatchItems : public std::enable_shared_from_this<WatchItems> {
 public:
  std::unique_ptr<WatchItems> Create(NSString *config_path, uint64_t reapply_config_frequency_secs);
  WatchItems(NSString *config_path_, dispatch_source_t timer_source);

  void BeginPeriodicTask();
  void ReloadConfig();

 private:
  NSString *config_path_;
  dispatch_source_t timer_source_;
  santa::common::PrefixTree<std::shared_ptr<WatchItem>> watch_items_;
  bool periodic_task_started_ = false;
  NSDictionary *current_config_ = nil;
};

}  // namespace santa::santad::data_layer

#endif
