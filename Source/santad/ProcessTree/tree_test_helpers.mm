/// Copyright 2023 Google LLC
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
#import <Foundation/Foundation.h>

#include <memory>
#include <string_view>

#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/tree.h"

namespace process_tree {
class ProcessTreeTestPeer : public ProcessTree {
 public:
  std::shared_ptr<const Process> InsertInit();
};

std::shared_ptr<const Process> ProcessTreeTestPeer::InsertInit() {
  absl::MutexLock lock(&mtx_);
  struct pid initpid = {
    .pid = 1,
    .pidversion = 1,
  };
  auto proc = std::make_shared<Process>(
    initpid, (cred){.uid = 0, .gid = 0},
    std::make_shared<program>((program){.executable = "/init", .arguments = {"/init"}}), nullptr);
  map_.emplace(initpid, proc);
  return proc;
}

}  // namespace process_tree
