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
  kSantaUserClientAcknowledgeBinary,
  kSantaUserClientClearCache,
  kSantaUserClientCacheCount,
  kSantaUserClientCheckCache,
  kSantaUserClientCacheBucketCount,

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
  ACTION_RESPOND_TOOLONG = 22,
  ACTION_RESPOND_ACK = 23,

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

// Struct to manage vnode IDs
typedef struct santa_vnode_id_t {
  uint64_t fsid;
  uint64_t fileid;

#ifdef __cplusplus
  bool operator==(const santa_vnode_id_t& rhs) const {
    return fsid == rhs.fsid && fileid == rhs.fileid;
  }
  // This _must not_ be used for anything security-sensitive. It exists solely to make
  // the msleep/wakeup calls easier.
  uint64_t unsafe_simple_id() const {
    return (((uint64_t)fsid << 32) | fileid);
  }
#endif
} santa_vnode_id_t;

// Message struct that is sent down the IODataQueue.
typedef struct {
  santa_action_t action;
  santa_vnode_id_t vnode_id;
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

// Used for the kSantaUserClientCacheBucketCount request.
typedef struct {
  uint16_t per_bucket[1024];
  uint64_t start;
} santa_bucket_count_t;

#endif  // SANTA__COMMON__KERNELCOMMON_H
