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
#include "Source/santad/ProcessTree/process_tree.h"

#include <libproc.h>

#include <memory>
#include <vector>

#include "Source/santad/ProcessTree/process.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace process_tree {

absl::StatusOr<Process> LoadPID(pid_t pid) {
  // TODO
  return absl::UnimplementedError("LoadPID not implemented");
}

absl::Status ProcessTree::Backfill() {
  int n_procs = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
  if (n_procs < 0) {
    return absl::InternalError("proc_listpids failed");
  }
  n_procs /= sizeof(pid_t);

  std::vector<pid_t> pids;
  pids.resize(n_procs + 16);  // add space for a few more processes
                              // in case some spawn in-between.

  n_procs =
      proc_listpids(PROC_ALL_PIDS, 0, pids.data(), (int)(pids.size() * sizeof(pid_t)));
  if (n_procs < 0) {
    return absl::InternalError("proc_listpids failed");
  }
  n_procs /= sizeof(pid_t);
  pids.resize(n_procs);

  absl::flat_hash_map<pid_t, std::vector<const Process>> parent_map;
  for (pid_t pid : pids) {
    auto proc_status = LoadPID(pid);
    if (proc_status.ok()) {
      auto unlinked_proc = proc_status.value();

      // Determine ppid
      // Alternatively, there's a sysctl interface:
      //  https://chromium.googlesource.com/chromium/chromium/+/master/base/process_util_openbsd.cc#32
      struct proc_bsdinfo bsdinfo;
      if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdinfo, sizeof(bsdinfo)) !=
          PROC_PIDTBSDINFO_SIZE) {
        continue;
      };

      parent_map[bsdinfo.pbi_ppid].push_back(unlinked_proc);
    }
  }

  auto &roots = parent_map[0];
  for (const Process &p : roots) {
    BackfillInsertChildren(parent_map, std::shared_ptr<Process>(), p);
  }

  return absl::OkStatus();
}

}  // namespace process_tree
