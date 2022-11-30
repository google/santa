/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdint.h>
#include <sys/param.h>

// Branch prediction
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

// Struct to manage vnode IDs
typedef struct SantaVnode {
  dev_t fsid;
  ino_t fileid;

#ifdef __cplusplus
  bool operator==(const SantaVnode &rhs) const {
    return fsid == rhs.fsid && fileid == rhs.fileid;
  }

  static inline SantaVnode VnodeForFile(const es_file_t *es_file) {
    return SantaVnode{
        .fsid = es_file->stat.st_dev,
        .fileid = es_file->stat.st_ino,
    };
  }
#endif
} SantaVnode;

#endif  // SANTA__COMMON__COMMON_H
