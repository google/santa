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
  ACTION_UNSET,

  // REQUESTS
  // If an operation is awaiting a cache decision from a similar operation
  // currently being processed, it will poll about every 5 ms for an answer.
  ACTION_REQUEST_BINARY,

  // RESPONSES
  ACTION_RESPOND_ALLOW,
  ACTION_RESPOND_DENY,
  ACTION_RESPOND_ALLOW_COMPILER,

} santa_action_t;

#define RESPONSE_VALID(x)                                   \
  (x == ACTION_RESPOND_ALLOW || x == ACTION_RESPOND_DENY || \
   x == ACTION_RESPOND_ALLOW_COMPILER)

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

#endif  // SANTA__COMMON__COMMON_H
