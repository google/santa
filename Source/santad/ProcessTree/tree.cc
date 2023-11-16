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
#include "Source/santad/ProcessTree/tree.h"

#include <libproc.h>

#include <algorithm>
#include <functional>
#include <memory>
#include <typeindex>
#include <typeinfo>
#include <vector>

#include "Source/santad/ProcessTree/Annotations/base.h"
#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"
#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"

namespace process_tree {

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
      proc_listpids(PROC_ALL_PIDS, 0, pids.data(), pids.size() * sizeof(pid_t));
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

void ProcessTree::BackfillInsertChildren(
    absl::flat_hash_map<pid_t, std::vector<const Process>> &parent_map,
    std::shared_ptr<Process> parent, const Process &unlinked_proc) {
  // We could also pull e.g. start time, pgid, associated tty, etc. from
  // bsdinfo here.
  auto proc = std::make_shared<Process>(
      unlinked_proc.pid_, unlinked_proc.effective_cred_,
      // Re-use shared pointers from parent if value equivalent
      (parent && *(unlinked_proc.program_) == *(parent->program_))
          ? parent->program_
          : unlinked_proc.program_,
      parent);
  {
    absl::MutexLock lock(&mtx_);
    map_.emplace(unlinked_proc.pid_, proc);
  }

  // The only case where we should not have a parent is the root processes
  // (e.g. init, kthreadd).
  if (parent) {
    for (auto &annotator : annotators_) {
      annotator->AnnotateFork(*this, *(proc->parent_), *proc);
      if (proc->program_ != proc->parent_->program_) {
        annotator->AnnotateExec(*this, *(proc->parent_), *proc);
      }
    }
  }

  for (const Process &child : parent_map[unlinked_proc.pid_.pid]) {
    BackfillInsertChildren(parent_map, proc, child);
  }
}

void ProcessTree::HandleFork(uint64_t timestamp, const Process &parent,
                             const pid new_pid) {
    if (Step(timestamp)) {
  std::shared_ptr<Process> child;
  {
    absl::MutexLock lock(&mtx_);
    child = std::make_shared<Process>(new_pid, parent.effective_cred_,
                                      parent.program_, map_[parent.pid_]);
    map_.emplace(new_pid, child);
  }
  for (const auto &annotator : annotators_) {
    annotator->AnnotateFork(*this, parent, *child);
  }
    }
}

void ProcessTree::HandleExec(uint64_t timestamp, const Process &p,
                             const pid new_pid, const program prog,
                             const cred c) {
if (Step(timestamp)) {
  // TODO(nickmg): should struct pid be reworked and only pid_version be passed?
  assert(new_pid.pid == p.pid_.pid);

  auto new_proc = std::make_shared<Process>(
      new_pid, c, std::make_shared<const program>(prog), p.parent_);
  {
    absl::MutexLock lock(&mtx_);
    remove_at_.push_back({timestamp, p.pid_});
    map_.emplace(new_proc->pid_, new_proc);
  }
  for (const auto &annotator : annotators_) {
    annotator->AnnotateExec(*this, p, *new_proc);
  }
}
}

void ProcessTree::HandleExit(uint64_t timestamp, const Process &p) {
  if (Step(timestamp)) {
  absl::MutexLock lock(&mtx_);
      remove_at_.push_back({timestamp, p.pid_});
    }
}

bool ProcessTree::Step(uint64_t timestamp) {
  absl::MutexLock lock(&mtx_);
  uint64_t new_cutoff = seen_timestamps_.front();
  if (timestamp < new_cutoff) {
    // Event timestamp is before the rolling list of seen events.
    // This event may or may not have been processed, but be conservative and
    // do not reprocess.
    return false;
  }

  if (std::binary_search(seen_timestamps_.begin(), seen_timestamps_.end(),
                         timestamp)) {
    // Event seen, signal it should not be reprocessed.
    return false;
  }

  auto insert_point =
      std::find_if(seen_timestamps_.rbegin(), seen_timestamps_.rend(),
                   [&](uint64_t x) { return x < timestamp; });
  std::move(seen_timestamps_.begin() + 1, insert_point.base(),
            seen_timestamps_.begin());
  *insert_point = timestamp;

  for (auto it = remove_at_.begin(); it != remove_at_.end();) {
    if (it->first < new_cutoff) {
      if (auto target = GetLocked(it->second);
          target && (*target)->refcnt_ > 0) {
        (*target)->tombstoned_ = true;
      } else {
        map_.erase(it->second);
      }
      it = remove_at_.erase(it);
    } else {
      it++;
    }
  }

  return true;
}

void ProcessTree::RetainProcess(const struct pid p) {
  absl::MutexLock lock(&mtx_);
  auto proc = GetLocked(p);
  if (proc) {
    (*proc)->refcnt_++;
  }
}

void ProcessTree::ReleaseProcess(const struct pid p) {
  absl::MutexLock lock(&mtx_);
  auto proc = GetLocked(p);
  if (proc) {
    if (--(*proc)->refcnt_ == 0 && (*proc)->tombstoned_) {
      map_.erase(p);
    }
  }
}

/*
---
Annotation get/set
---
*/

void ProcessTree::RegisterAnnotator(std::unique_ptr<Annotator> a) {
  annotators_.push_back(std::move(a));
}

void ProcessTree::AnnotateProcess(const Process &p,
                                  std::shared_ptr<const Annotator> a) {
  absl::MutexLock lock(&mtx_);
  const Annotator &x = *a;
  map_[p.pid_]->annotations_.emplace(std::type_index(typeid(x)), std::move(a));
}

std::optional<pb::Annotations> ProcessTree::GetAnnotations(const pid p) {
  auto proc = Get(p);
  if (!proc || (*proc)->annotations_.size() == 0) {
    return std::nullopt;
  }
  pb::Annotations a;
  for (const auto &[_, annotation] : (*proc)->annotations_) {
    if (auto x = annotation->Proto(); x) a.MergeFrom(*x);
  }
  return a;
}

/*
---
Tree inspection methods
---
*/

std::vector<std::shared_ptr<const Process>> ProcessTree::RootSlice(
    std::shared_ptr<const Process> p) const {
  std::vector<std::shared_ptr<const Process>> slice;
  while (p) {
    slice.push_back(p);
    p = p->parent_;
  }
  return slice;
}

void ProcessTree::Iterate(
    std::function<void(std::shared_ptr<const Process> p)> f) const {
  std::vector<std::shared_ptr<const Process>> procs;
  {
    absl::ReaderMutexLock lock(&mtx_);
    procs.reserve(map_.size());
    for (auto &[_, proc] : map_) {
      procs.push_back(proc);
    }
  }

  for (auto &p : procs) {
    f(p);
  }
}

std::optional<std::shared_ptr<const Process>> ProcessTree::Get(
    const pid target) const {
  absl::ReaderMutexLock lock(&mtx_);
  return GetLocked(target);
}

std::optional<std::shared_ptr<Process>> ProcessTree::GetLocked(
    const pid target) const {
  auto it = map_.find(target);
  if (it == map_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::shared_ptr<const Process> ProcessTree::GetParent(const Process &p) const {
  return p.parent_;
}

void ProcessTree::DebugDump(std::ostream &stream) const {
  absl::ReaderMutexLock lock(&mtx_);
  stream << map_.size() << " processes" << std::endl;
  DebugDumpLocked(stream, 0, 0);
}

void ProcessTree::DebugDumpLocked(std::ostream &stream, int depth,
                                  pid_t ppid) const
    ABSL_SHARED_LOCKS_REQUIRED(mtx_) {
  for (auto &[_, process] : map_) {
    if ((ppid == 0 && !process->parent_) ||
        (process->parent_ && process->parent_->pid_.pid == ppid)) {
      stream << std::string(2 * depth, ' ') << process->pid_.pid
             << process->program_->executable << std::endl;
      DebugDumpLocked(stream, depth + 1, process->pid_.pid);
    }
  }
}

/*
----
Tokens
----
*/

ProcessToken::ProcessToken(std::shared_ptr<ProcessTree> tree,
                           std::vector<struct pid> pids)
    : tree_(std::move(tree)), pids_(std::move(pids)) {
  for (const struct pid &p : pids_) {
    tree_->RetainProcess(p);
  }
}

ProcessToken::~ProcessToken() {
  for (const struct pid &p : pids_) {
    tree_->ReleaseProcess(p);
  }
}

}  // namespace process_tree
