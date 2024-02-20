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

#include <Foundation/Foundation.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <mach/message.h>
#include <string.h>
#include <sys/sysctl.h>

#include <memory>
#include <vector>

#include "Source/santad/ProcessTree/process.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace santa::santad::process_tree {

namespace {
// Modified from
// https://chromium.googlesource.com/crashpad/crashpad/+/360e441c53ab4191a6fd2472cc57c3343a2f6944/util/posix/process_util_mac.cc
// TODO: https://github.com/apple-oss-distributions/adv_cmds/blob/main/ps/ps.c
absl::StatusOr<std::vector<std::string>> ProcessArgumentsForPID(pid_t pid) {
  // The format of KERN_PROCARGS2 is explained in 10.9.2 adv_cmds-153/ps/print.c
  // getproclline(). It is an int (argc) followed by the executable’s string
  // area. The string area consists of NUL-terminated strings, beginning with
  // the executable path, and then starting on an aligned boundary, all of the
  // elements of argv, envp, and applev.
  // It is possible for a process to exec() in between the two sysctl() calls
  // below. If that happens, and the string area of the new program is larger
  // than that of the old one, args_size_estimate will be too small. To detect
  // this situation, the second sysctl() attempts to fetch args_size_estimate +
  // 1 bytes, expecting to only receive args_size_estimate. If it gets the extra
  // byte, it indicates that the string area has grown, and the sysctl() pair
  // will be retried a limited number of times.
  size_t args_size_estimate;
  size_t args_size;
  std::string args;
  int tries = 3;
  do {
    int mib[] = {CTL_KERN, KERN_PROCARGS2, pid};
    int rv = sysctl(mib, 3, nullptr, &args_size_estimate, nullptr, 0);
    if (rv != 0) {
      return absl::InternalError("KERN_PROCARGS2");
    }
    args_size = args_size_estimate + 1;
    args.resize(args_size);
    rv = sysctl(mib, 3, &args[0], &args_size, nullptr, 0);
    if (rv != 0) {
      return absl::InternalError("KERN_PROCARGS2");
    }
  } while (args_size == args_size_estimate + 1 && tries--);
  if (args_size == args_size_estimate + 1) {
    return absl::InternalError("Couldn't determine size");
  }
  // KERN_PROCARGS2 needs to at least contain argc.
  if (args_size < sizeof(int)) {
    return absl::InternalError("Bad args_size");
  }
  args.resize(args_size);
  // Get argc.
  int argc;
  memcpy(&argc, &args[0], sizeof(argc));
  // Find the end of the executable path.
  size_t start_pos = sizeof(argc);
  size_t nul_pos = args.find('\0', start_pos);
  if (nul_pos == std::string::npos) {
    return absl::InternalError("Can't find end of executable path");
  }
  // Find the beginning of the string area.
  start_pos = args.find_first_not_of('\0', nul_pos);
  if (start_pos == std::string::npos) {
    return absl::InternalError("Can't find args after executable path");
  }
  std::vector<std::string> local_argv;
  while (argc-- && nul_pos != std::string::npos) {
    nul_pos = args.find('\0', start_pos);
    local_argv.push_back(args.substr(start_pos, nul_pos - start_pos));
    start_pos = nul_pos + 1;
  }
  return local_argv;
}
}  // namespace

struct Pid PidFromAuditToken(const audit_token_t &tok) {
  return (struct Pid){.pid = audit_token_to_pid(tok),
                      .pidversion = (uint64_t)audit_token_to_pidversion(tok)};
}

absl::StatusOr<Process> LoadPID(pid_t pid) {
  task_name_t task;
  mach_msg_type_number_t size = TASK_AUDIT_TOKEN_COUNT;
  audit_token_t token;

  if (task_name_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
    return absl::InternalError("task_name_for_pid");
  }

  if (task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &size) != KERN_SUCCESS) {
    return absl::InternalError("task_info(TASK_AUDIT_TOKEN)");
  }
  mach_port_deallocate(mach_task_self(), task);

  char path[PROC_PIDPATHINFO_MAXSIZE];
  if (proc_pidpath_audittoken(&token, path, sizeof(path)) <= 0) {
    return absl::InternalError("proc_pidpath_audittoken");
  }

  // Don't fail Process creation if args can't be recovered.
  std::vector<std::string> args =
    ProcessArgumentsForPID(audit_token_to_pid(token)).value_or(std::vector<std::string>());

  return Process((struct Pid){.pid = audit_token_to_pid(token),
                              .pidversion = (uint64_t)audit_token_to_pidversion(token)},
                 (struct Cred){
                   .uid = audit_token_to_euid(token),
                   .gid = audit_token_to_egid(token),
                 },
                 std::make_shared<struct Program>((struct Program){
                   .executable = path,
                   .arguments = args,
                 }),
                 nullptr);
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

  n_procs = proc_listpids(PROC_ALL_PIDS, 0, pids.data(), (int)(pids.size() * sizeof(pid_t)));
  if (n_procs < 0) {
    return absl::InternalError("proc_listpids failed");
  }
  n_procs /= sizeof(pid_t);
  pids.resize(n_procs);

  absl::flat_hash_map<pid_t, std::vector<Process>> parent_map;
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

}  // namespace santa::santad::process_tree
