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
/// Common defines between daemon <-> client
///

#ifndef SANTA__COMMON__COMMON_H
#define SANTA__COMMON__COMMON_H

#include <stdint.h>
#include <sys/param.h>

// Branch prediction
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

typedef enum {
  ACTION_UNSET = 0,

  // REQUESTS
  ACTION_REQUEST_SHUTDOWN = 10, // TODO: Remove
  // If an operation is awaiting a cache decision from a similar operation
  // currently being processed, it will poll about every 5 ms for an answer.
  ACTION_REQUEST_BINARY = 11,

  // RESPONSES
  ACTION_RESPOND_ALLOW = 20,
  ACTION_RESPOND_DENY = 21,
  ACTION_RESPOND_TOOLONG = 22, // TODO: Remove
  ACTION_RESPOND_ACK = 23,     // TODO: Remove
  ACTION_RESPOND_ALLOW_COMPILER = 24,
  // The following response is stored only in the kernel decision cache.
  // It is removed by SNTCompilerController
  ACTION_RESPOND_ALLOW_PENDING_TRANSITIVE = 25, // TODO: Remove?

  // NOTIFY
  ACTION_NOTIFY_EXEC = 30,
  ACTION_NOTIFY_WRITE = 31,
  ACTION_NOTIFY_RENAME = 32,
  ACTION_NOTIFY_LINK = 33,
  ACTION_NOTIFY_EXCHANGE = 34,
  ACTION_NOTIFY_DELETE = 35,
  ACTION_NOTIFY_WHITELIST = 36,
  ACTION_NOTIFY_FORK = 37,
  ACTION_NOTIFY_EXIT = 38,

  // ERROR
  ACTION_ERROR = 99,
} santa_action_t;

#define RESPONSE_VALID(x)                                   \
  (x == ACTION_RESPOND_ALLOW || x == ACTION_RESPOND_DENY || \
   x == ACTION_RESPOND_ALLOW_COMPILER ||                    \
   x == ACTION_RESPOND_ALLOW_PENDING_TRANSITIVE)

// Struct to manage vnode IDs
typedef struct santa_vnode_id_t {
  uint64_t fsid;
  uint64_t fileid;

#ifdef __cplusplus
  bool operator==(const santa_vnode_id_t &rhs) const {
    return fsid == rhs.fsid && fileid == rhs.fileid;
  }
#endif
} santa_vnode_id_t;

// typedef struct {
//   santa_action_t action;
//   santa_vnode_id_t vnode_id;
//   uid_t uid;
//   gid_t gid;
//   pid_t pid;
//   int pidversion;
//   pid_t ppid;
//   char path[MAXPATHLEN];
//   char newpath[MAXPATHLEN];
//   char ttypath[MAXPATHLEN];
//   // For file events, this is the process name.
//   // For exec requests, this is the parent process name.
//   // While process names can technically be 4*MAXPATHLEN, that never
//   // actually happens, so only take MAXPATHLEN and throw away any excess.
//   char pname[MAXPATHLEN];

//   // This points to a copy of the original ES message.
//   void *es_message;

//   // This points to an NSArray of the process arguments.
//   void *args_array;
// } santa_message_t;

#endif  // SANTA__COMMON__COMMON_H
