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

#include "Source/common/Platform.h"
#include "Source/common/SystemResources.h"

NSString *RepeatedString(NSString *str, NSUInteger len) {
  return [@"" stringByPaddingToLength:len withString:str startingAtIndex:0];
}

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
    .length = s ? strlen(s) : 0,
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

es_message_t MakeESMessage(es_event_type_t et, es_process_t *proc, ActionType action_type,
                           uint64_t future_deadline_ms) {
  es_message_t es_msg = {
    .deadline = AddNanosecondsToMachTime(future_deadline_ms * NSEC_PER_MSEC, mach_absolute_time()),
    .process = proc,
    .action_type =
      (action_type == ActionType::Notify) ? ES_ACTION_TYPE_NOTIFY : ES_ACTION_TYPE_AUTH,
    .event_type = et,
  };

  es_msg.version = MaxSupportedESMessageVersionForCurrentOS();

  return es_msg;
}

void SleepMS(long ms) {
  struct timespec ts {
    .tv_sec = ms / 1000, .tv_nsec = (long)((ms % 1000) * NSEC_PER_MSEC),
  };

  while (nanosleep(&ts, &ts) != 0) {
    XCTAssertEqual(errno, EINTR);
  }
}

uint32_t MaxSupportedESMessageVersionForCurrentOS() {
  // Note 1: This function only returns a subset of versions. This is due to the
  // minimum supported OS build version as well as features in latest versions
  // not currently being used. Capping the max means unnecessary duuplicate test
  // JSON files are not needed.
  //
  // Note 2: The following table maps ES message versions to lmin macOS version:
  //   ES Version | macOS Version
  //            1 | 10.15.0
  //            2 | 10.15.4
  //            3 | Only in a beta
  //            4 | 11.0
  //            5 | 12.3
  //            6 | 13.0
  //            7 | 14.0
  //            8 | 15.0
  if (@available(macOS 13.0, *)) {
    return 6;
  } else if (@available(macOS 12.3, *)) {
    return 5;
  } else {
    return 4;
  }
}

uint32_t MinSupportedESMessageVersion(es_event_type_t event_type) {
  switch (event_type) {
    // The following events are available beginning in macOS 10.15
    case ES_EVENT_TYPE_AUTH_EXEC:
    case ES_EVENT_TYPE_AUTH_OPEN:
    case ES_EVENT_TYPE_AUTH_KEXTLOAD:
    case ES_EVENT_TYPE_AUTH_MMAP:
    case ES_EVENT_TYPE_AUTH_MPROTECT:
    case ES_EVENT_TYPE_AUTH_MOUNT:
    case ES_EVENT_TYPE_AUTH_RENAME:
    case ES_EVENT_TYPE_AUTH_SIGNAL:
    case ES_EVENT_TYPE_AUTH_UNLINK:
    case ES_EVENT_TYPE_NOTIFY_EXEC:
    case ES_EVENT_TYPE_NOTIFY_OPEN:
    case ES_EVENT_TYPE_NOTIFY_FORK:
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
    case ES_EVENT_TYPE_NOTIFY_CREATE:
    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
    case ES_EVENT_TYPE_NOTIFY_EXIT:
    case ES_EVENT_TYPE_NOTIFY_GET_TASK:
    case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
    case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
    case ES_EVENT_TYPE_NOTIFY_LINK:
    case ES_EVENT_TYPE_NOTIFY_MMAP:
    case ES_EVENT_TYPE_NOTIFY_MPROTECT:
    case ES_EVENT_TYPE_NOTIFY_MOUNT:
    case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
    case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
    case ES_EVENT_TYPE_NOTIFY_RENAME:
    case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
    case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
    case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
    case ES_EVENT_TYPE_NOTIFY_SETMODE:
    case ES_EVENT_TYPE_NOTIFY_SETOWNER:
    case ES_EVENT_TYPE_NOTIFY_SIGNAL:
    case ES_EVENT_TYPE_NOTIFY_UNLINK:
    case ES_EVENT_TYPE_NOTIFY_WRITE:
    case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE:
    case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
    case ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE:
    case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
    case ES_EVENT_TYPE_AUTH_READLINK:
    case ES_EVENT_TYPE_NOTIFY_READLINK:
    case ES_EVENT_TYPE_AUTH_TRUNCATE:
    case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
    case ES_EVENT_TYPE_AUTH_LINK:
    case ES_EVENT_TYPE_NOTIFY_LOOKUP:
    case ES_EVENT_TYPE_AUTH_CREATE:
    case ES_EVENT_TYPE_AUTH_SETATTRLIST:
    case ES_EVENT_TYPE_AUTH_SETEXTATTR:
    case ES_EVENT_TYPE_AUTH_SETFLAGS:
    case ES_EVENT_TYPE_AUTH_SETMODE:
    case ES_EVENT_TYPE_AUTH_SETOWNER: return 1;

    // The following events are available beginning in macOS 10.15.1
    case ES_EVENT_TYPE_AUTH_CHDIR:
    case ES_EVENT_TYPE_NOTIFY_CHDIR:
    case ES_EVENT_TYPE_AUTH_GETATTRLIST:
    case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
    case ES_EVENT_TYPE_NOTIFY_STAT:
    case ES_EVENT_TYPE_NOTIFY_ACCESS:
    case ES_EVENT_TYPE_AUTH_CHROOT:
    case ES_EVENT_TYPE_NOTIFY_CHROOT:
    case ES_EVENT_TYPE_AUTH_UTIMES:
    case ES_EVENT_TYPE_NOTIFY_UTIMES:
    case ES_EVENT_TYPE_AUTH_CLONE:
    case ES_EVENT_TYPE_NOTIFY_CLONE:
    case ES_EVENT_TYPE_NOTIFY_FCNTL:
    case ES_EVENT_TYPE_AUTH_GETEXTATTR:
    case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
    case ES_EVENT_TYPE_AUTH_LISTEXTATTR:
    case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
    case ES_EVENT_TYPE_AUTH_READDIR:
    case ES_EVENT_TYPE_NOTIFY_READDIR:
    case ES_EVENT_TYPE_AUTH_DELETEEXTATTR:
    case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
    case ES_EVENT_TYPE_AUTH_FSGETPATH:
    case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
    case ES_EVENT_TYPE_NOTIFY_DUP:
    case ES_EVENT_TYPE_AUTH_SETTIME:
    case ES_EVENT_TYPE_NOTIFY_SETTIME:
    case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
    case ES_EVENT_TYPE_AUTH_UIPC_BIND:
    case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
    case ES_EVENT_TYPE_AUTH_UIPC_CONNECT:
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
    case ES_EVENT_TYPE_AUTH_SETACL:
    case ES_EVENT_TYPE_NOTIFY_SETACL: return 1;

    // The following events are available beginning in macOS 10.15.4
    case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
    case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE:
    case ES_EVENT_TYPE_AUTH_PROC_CHECK:
    case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
    case ES_EVENT_TYPE_AUTH_GET_TASK: return 2;

    // The following events are available beginning in macOS 11.0
    case ES_EVENT_TYPE_AUTH_SEARCHFS:
    case ES_EVENT_TYPE_NOTIFY_SEARCHFS:
    case ES_EVENT_TYPE_AUTH_FCNTL:
    case ES_EVENT_TYPE_AUTH_IOKIT_OPEN:
    case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME:
    case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
    case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
    case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME:
    case ES_EVENT_TYPE_NOTIFY_TRACE:
    case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
    case ES_EVENT_TYPE_AUTH_REMOUNT:
    case ES_EVENT_TYPE_NOTIFY_REMOUNT: return 4;

    // The following events are available beginning in macOS 11.3
    case ES_EVENT_TYPE_AUTH_GET_TASK_READ:
    case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
    case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT: return 4;

    // The following events are available beginning in macOS 12.0
    case ES_EVENT_TYPE_NOTIFY_SETUID:
    case ES_EVENT_TYPE_NOTIFY_SETGID:
    case ES_EVENT_TYPE_NOTIFY_SETEUID:
    case ES_EVENT_TYPE_NOTIFY_SETEGID:
    case ES_EVENT_TYPE_NOTIFY_SETREUID:
    case ES_EVENT_TYPE_NOTIFY_SETREGID:
    case ES_EVENT_TYPE_AUTH_COPYFILE:
    case ES_EVENT_TYPE_NOTIFY_COPYFILE: return 4;

#if HAVE_MACOS_13
    // The following events are available beginning in macOS 13.0
    case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION:
    case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED:
    case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED:
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN:
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT:
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK:
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK:
    case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH:
    case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH:
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN:
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT:
    case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN:
    case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT:
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE: return 6;
#endif

#if HAVE_MACOS_14
    // The following events are available beginning in macOS 14.0
    case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD:
    case ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE:
    case ES_EVENT_TYPE_NOTIFY_SU:
    case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION:
    case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT:
    case ES_EVENT_TYPE_NOTIFY_SUDO:
    case ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD:
    case ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE:
    case ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET:
    case ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD:
    case ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER:
    case ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER:
    case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD:
    case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE:
    case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET:
    case ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER:
    case ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP:
    case ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER:
    case ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP:
    case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT: return 7;
#endif

#if HAVE_MACOS_15
    case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE: return 8;
#endif

    default: return UINT32_MAX;
  }
}
