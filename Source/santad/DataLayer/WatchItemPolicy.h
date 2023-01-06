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

#include <string>
#include <string_view>
#include <vector>

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
  struct Process {
    Process(std::string bp, std::string ti, std::vector<uint8_t> cdh,
            std::string ch)
        : binary_path(bp),
          team_id(ti),
          cdhash(std::move(cdh)),
          certificate_sha256(ch) {}
    std::string binary_path;
    std::string team_id;
    std::vector<uint8_t> cdhash;
    std::string certificate_sha256;
  };

  WatchItemPolicy(std::string_view n, std::string_view p,
                  WatchItemPathType pt = kWatchItemPolicyDefaultPathType,
                  bool ara = kWatchItemPolicyDefaultAllowReadAccess,
                  bool ao = kWatchItemPolicyDefaultAuditOnly,
                  std::vector<Process> procs = {})
      : name(n),
        path(p),
        path_type(pt),
        allow_read_access(ara),
        audit_only(ao),
        processes(std::move(procs)) {}

  std::string name;
  std::string path;
  WatchItemPathType path_type;
  bool allow_read_access;
  bool audit_only;
  std::vector<Process> processes;
};

}  // namespace santa::santad::data_layer

#endif
