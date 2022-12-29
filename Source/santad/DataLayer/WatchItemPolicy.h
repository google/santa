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

#ifndef SANTA__SANTAD__DATALAYER_WATCHITEMPOLICY_H
#define SANTA__SANTAD__DATALAYER_WATCHITEMPOLICY_H

#include <Kernel/kern/cs_blobs.h>

#include <array>
#include <set>
#include <string>
#include <string_view>

namespace santa::santad::data_layer {

enum class WatchItemPathType {
  kPrefix,
  kLiteral,
};

static constexpr WatchItemPathType kWatchItemPolicyDefaultPathType =
    WatchItemPathType::kLiteral;
static constexpr bool kWatchItemPolicyDefaultAllowReadAccess = false;
static constexpr bool kWatchItemPolicyDefaultAuditOnly = true;

struct WatchItemPolicy {
  WatchItemPolicy(std::string_view n, std::string_view p,
                  WatchItemPathType pt = kWatchItemPolicyDefaultPathType,
                  bool ara = kWatchItemPolicyDefaultAllowReadAccess,
                  bool ao = kWatchItemPolicyDefaultAuditOnly,
                  std::set<std::string> abp = {},
                  std::set<std::string> ati = {},
                  std::set<std::array<uint8_t, CS_CDHASH_LEN>> ach = {},
                  std::set<std::string> acs = {})
      : name(n),
        path(p),
        path_type(pt),
        allow_read_access(ara),
        audit_only(ao),
        allowed_binary_paths(std::move(abp)),
        allowed_team_ids(std::move(ati)),
        allowed_cdhashes(std::move(ach)),
        allowed_certificates_sha256(std::move(acs)) {}

  std::string name;
  std::string path;
  WatchItemPathType path_type;
  bool allow_read_access;
  bool audit_only;
  std::set<std::string> allowed_binary_paths;
  std::set<std::string> allowed_team_ids;
  std::set<std::array<uint8_t, CS_CDHASH_LEN>> allowed_cdhashes;
  std::set<std::string> allowed_certificates_sha256;
};

}  // namespace santa::santad::data_layer

#endif
