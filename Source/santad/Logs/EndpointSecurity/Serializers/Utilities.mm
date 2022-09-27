/// Copyright 2022 Google LLC
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

#include "Source/santad/Logs/EndpointSecurity/Serializers/Utilities.h"

// #include <bsm/libbsm.h>
// #include <EndpointSecurity/EndpointSecurity.h>
// #import <Foundation/Foundation.h>

// These functions are exported by the Security framework, but are not included in headers
extern "C" Boolean SecTranslocateIsTranslocatedURL(CFURLRef path, bool *isTranslocated,
                                                   CFErrorRef *__nullable error);
extern "C" CFURLRef __nullable SecTranslocateCreateOriginalPathForURL(CFURLRef translocatedPath,
                                                                      CFErrorRef *__nullable error);

namespace santa::santad::logs::endpoint_security::serializers::Utilities {

static inline void SetThreadIDs(uid_t uid, gid_t gid) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated"
  pthread_setugid_np(uid, gid);
#pragma clang diagnostic pop
}

NSString *OriginalPathForTranslocation(const es_process_t *es_proc) {
  if (!es_proc) {
    return nil;
  }

  // Note: Benchmarks showed better performance using `URLWithString` with a `file://` prefix
  // compared to using `fileURLWithPath`.
  CFURLRef cfExecURL = (__bridge CFURLRef)
    [NSURL URLWithString:[NSString stringWithFormat:@"file://%s", es_proc->executable->path.data]];
  NSURL *origURL = nil;
  bool isTranslocated = false;

  if (SecTranslocateIsTranslocatedURL(cfExecURL, &isTranslocated, NULL) && isTranslocated) {
    bool dropPrivs = true;
    if (@available(macOS 12.0, *)) {
      dropPrivs = false;
    }

    if (dropPrivs) {
      SetThreadIDs(RealUser(es_proc->audit_token), RealGroup(es_proc->audit_token));
    }

    origURL = CFBridgingRelease(SecTranslocateCreateOriginalPathForURL(cfExecURL, NULL));

    if (dropPrivs) {
      SetThreadIDs(KAUTH_UID_NONE, KAUTH_GID_NONE);
    }
  }

  return [origURL path];
}

}  // namespace santa::santad::logs::endpoint_security::serializers::Utilities
