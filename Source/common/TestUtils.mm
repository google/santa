/// Copyright 2022 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#include "Source/common/TestUtils.h"

#include <EndpointSecurity/ESTypes.h>
#include <dispatch/dispatch.h>
#include <mach/mach_time.h>
#include <time.h>
#include <uuid/uuid.h>

audit_token_t MakeAuditToken(pid_t pid, pid_t pidver) {
  return audit_token_t{
    .val =
      {
        0,
        NOBODY_UID,
        NOGROUP_GID,
        NOBODY_UID,
        NOGROUP_GID,
        (unsigned int)pid,
        0,
        (unsigned int)pidver,
      },
  };
}

struct stat MakeStat(int offset) {
  return (struct stat){
    .st_dev = 1 + offset,
    .st_mode = (mode_t)(2 + offset),
    .st_nlink = (nlink_t)(3 + offset),
    .st_ino = (uint64_t)(4 + offset),
    .st_uid = NOBODY_UID,
    .st_gid = NOGROUP_GID,
    .st_rdev = 5 + offset,
    .st_atimespec = {.tv_sec = 100 + offset, .tv_nsec = 200 + offset},
    .st_mtimespec = {.tv_sec = 101 + offset, .tv_nsec = 21 + offset},
    .st_ctimespec = {.tv_sec = 102 + offset, .tv_nsec = 202 + offset},
    .st_birthtimespec = {.tv_sec = 103 + offset, .tv_nsec = 203 + offset},
    .st_size = 6 + offset,
    .st_blocks = 7 + offset,
    .st_blksize = 8 + offset,
    .st_flags = (uint32_t)(9 + offset),
    .st_gen = (uint32_t)(10 + offset),
  };
}

es_string_token_t MakeESStringToken(const char *s) {
  return es_string_token_t{
    .length = strlen(s),
    .data = s,
  };
}

es_file_t MakeESFile(const char *path, struct stat sb) {
  return es_file_t{
    .path = MakeESStringToken(path),
    .path_truncated = false,
    .stat = sb,
  };
}

es_process_t MakeESProcess(es_file_t *file, audit_token_t tok, audit_token_t parent_tok) {
  return es_process_t{
    .audit_token = tok,
    .ppid = audit_token_to_pid(parent_tok),
    .original_ppid = audit_token_to_pid(parent_tok),
    .group_id = 111,
    .session_id = 222,
    .is_platform_binary = true,
    .is_es_client = true,
    .executable = file,
    .parent_audit_token = parent_tok,
  };
}

static uint64_t AddMillisToMachTime(uint64_t ms, uint64_t machTime) {
  static dispatch_once_t onceToken;
  static mach_timebase_info_data_t timebase;

  dispatch_once(&onceToken, ^{
    mach_timebase_info(&timebase);
  });

  // Convert given machTime to nanoseconds
  uint64_t nanoTime = machTime * timebase.numer / timebase.denom;

  // Add the ms offset
  nanoTime += (ms * NSEC_PER_MSEC);

  // Convert back to machTime
  return nanoTime * timebase.denom / timebase.numer;
}

es_message_t MakeESMessage(es_event_type_t et, es_process_t *proc, ActionType action_type,
                           uint64_t future_deadline_ms) {
  return es_message_t{
    .deadline = AddMillisToMachTime(future_deadline_ms, mach_absolute_time()),
    .process = proc,
    .action_type =
      (action_type == ActionType::Notify) ? ES_ACTION_TYPE_NOTIFY : ES_ACTION_TYPE_AUTH,
    .event_type = et,
  };
}

void SleepMS(long ms) {
  struct timespec ts {
    .tv_sec = ms / 1000, .tv_nsec = (long)((ms % 1000) * NSEC_PER_MSEC),
  };

  while (nanosleep(&ts, &ts) != 0) {
    XCTAssertEqual(errno, EINTR);
  }
}
