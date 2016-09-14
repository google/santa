/// Copyright 2015 Google Inc. All rights reserved.
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

///
/// Common defines between kernel <-> userspace
///

#include <sys/param.h>

#ifndef SANTA__COMMON__KERNELCOMMON_H
#define SANTA__COMMON__KERNELCOMMON_H

// Defines the lengths of paths and Vnode IDs passed around.
#define MAX_VNODE_ID_STR 21  // digits in UINT64_MAX + 1 for NULL-terminator

// Defines the name of the userclient class and the driver bundle ID.
#define USERCLIENT_CLASS "com_google_SantaDriver"
#define USERCLIENT_ID "com.google.santa-driver"

// Branch prediction
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

// List of methods supported by the driver.
enum SantaDriverMethods {
  kSantaUserClientOpen,
  kSantaUserClientAllowBinary,
  kSantaUserClientDenyBinary,
  kSantaUserClientClearCache,
  kSantaUserClientCacheCount,
  kSantaUserClientCheckCache,

  // Any methods supported by the driver should be added above this line to
  // ensure this remains the count of methods.
  kSantaUserClientNMethods,
};

typedef enum {
  QUEUETYPE_DECISION,
  QUEUETYPE_LOG
} santa_queuetype_t;

// Enum defining actions that can be passed down the IODataQueue and in
// response methods.
typedef enum {
  ACTION_UNSET = 0,

  // REQUESTS
  ACTION_REQUEST_SHUTDOWN = 10,
  ACTION_REQUEST_BINARY = 11,

  // RESPONSES
  ACTION_RESPOND_ALLOW = 20,
  ACTION_RESPOND_DENY = 21,

  // NOTIFY
  ACTION_NOTIFY_EXEC = 30,
  ACTION_NOTIFY_WRITE = 31,
  ACTION_NOTIFY_RENAME = 32,
  ACTION_NOTIFY_LINK = 33,
  ACTION_NOTIFY_EXCHANGE = 34,
  ACTION_NOTIFY_DELETE = 35,

  // ERROR
  ACTION_ERROR = 99,
} santa_action_t;

#define RESPONSE_VALID(x) \
  (x == ACTION_RESPOND_ALLOW || x == ACTION_RESPOND_DENY)

// Message struct that is sent down the IODataQueue.
typedef struct {
  santa_action_t action;
  uint64_t vnode_id;
  uid_t uid;
  gid_t gid;
  pid_t pid;
  pid_t ppid;
  char path[MAXPATHLEN];
  char newpath[MAXPATHLEN];
  // For file events, this is the process name.
  // For exec requests, this is the parent process name.
  // While process names can technically be 4*MAXPATHLEN, that never
  // actually happens, so only take MAXPATHLEN and throw away any excess.
  char pname[MAXPATHLEN];
} santa_message_t;

#endif  // SANTA__COMMON__KERNELCOMMON_H
