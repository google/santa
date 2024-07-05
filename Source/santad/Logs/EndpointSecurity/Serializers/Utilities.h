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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_UTILITIES_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_UTILITIES_H

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#include <bsm/libbsm.h>

#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

namespace santa {

static inline pid_t Pid(const audit_token_t &tok) {
  return audit_token_to_pid(tok);
}

static inline pid_t Pidversion(const audit_token_t &tok) {
  return audit_token_to_pidversion(tok);
}

static inline pid_t RealUser(const audit_token_t &tok) {
  return audit_token_to_ruid(tok);
}

static inline pid_t RealGroup(const audit_token_t &tok) {
  return audit_token_to_rgid(tok);
}

static inline pid_t EffectiveUser(const audit_token_t &tok) {
  return audit_token_to_euid(tok);
}

static inline pid_t EffectiveGroup(const audit_token_t &tok) {
  return audit_token_to_egid(tok);
}

static inline NSString *NonNull(NSString *str) {
  return str ?: @"";
}

NSString *OriginalPathForTranslocation(const es_process_t *es_proc);
NSString *SerialForDevice(NSString *devPath);
NSString *DiskImageForDevice(NSString *devPath);
NSString *MountFromName(NSString *path);

es_file_t *GetAllowListTargetFile(const santa::Message &msg);

const mach_port_t GetDefaultIOKitCommsPort();

}  // namespace santa

#endif
