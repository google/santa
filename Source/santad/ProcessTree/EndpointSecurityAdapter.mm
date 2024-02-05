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
#include <EndpointSecurity/EndpointSecurity.h>
#include <Foundation/Foundation.h>
#include <bsm/libbsm.h>

#include "Source/santad/ProcessTree/process_tree.h"
#include "Source/santad/ProcessTree/process_tree_macos.h"
#include "absl/status/statusor.h"

namespace santa::santad::process_tree {

void InformFromESEvent(ProcessTree &tree, const es_message_t *msg) {
  struct Pid event_pid = PidFromAuditToken(msg->process->audit_token);
  auto proc = tree.Get(event_pid);

  if (!proc) {
    return;
  }

  switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC:
    case ES_EVENT_TYPE_NOTIFY_EXEC: {
      std::vector<std::string> args;
      args.reserve(es_exec_arg_count(&msg->event.exec));
      for (int i = 0; i < es_exec_arg_count(&msg->event.exec); i++) {
        es_string_token_t arg = es_exec_arg(&msg->event.exec, i);
        args.push_back(std::string(arg.data, arg.length));
      }

      es_string_token_t executable = msg->event.exec.target->executable->path;
      tree.HandleExec(
        msg->mach_time, **proc, PidFromAuditToken(msg->event.exec.target->audit_token),
        (struct Program){.executable = std::string(executable.data, executable.length),
                         .arguments = args},
        (struct Cred){
          .uid = audit_token_to_euid(msg->event.exec.target->audit_token),
          .gid = audit_token_to_egid(msg->event.exec.target->audit_token),
        });

      break;
    }
    case ES_EVENT_TYPE_NOTIFY_FORK: {
      tree.HandleFork(msg->mach_time, **proc,
                      PidFromAuditToken(msg->event.fork.child->audit_token));
      break;
    }
    case ES_EVENT_TYPE_NOTIFY_EXIT: tree.HandleExit(msg->mach_time, **proc); break;
    default: return;
  }
}

}  // namespace santa::santad::process_tree
