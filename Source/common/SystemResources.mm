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

#include "Source/common/SystemResources.h"

#include <dispatch/dispatch.h>
#include <libproc.h>
#include <mach/kern_return.h>
#include <unistd.h>
#include <optional>

#include "Source/common/SNTLogging.h"

static mach_timebase_info_data_t GetTimebase() {
  static dispatch_once_t once_token;
  static mach_timebase_info_data_t timebase;

  dispatch_once(&once_token, ^{
    if (mach_timebase_info(&timebase) != KERN_SUCCESS) {
      // This shouldn't fail. Assume transitory and exit the program.
      // Hopefully fixes itself on restart...
      LOGE(@"Failed to get timebase info. Exiting.");
      exit(EXIT_FAILURE);
    }
  });

  return timebase;
}

uint64_t MachTimeToNanos(uint64_t mach_time) {
  mach_timebase_info_data_t timebase = GetTimebase();

  return mach_time * timebase.numer / timebase.denom;
}

uint64_t NanosToMachTime(uint64_t nanos) {
  mach_timebase_info_data_t timebase = GetTimebase();

  return nanos * timebase.denom / timebase.numer;
}

std::optional<SantaTaskInfo> GetTaskInfo() {
  struct proc_taskinfo pti;

  if (proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &pti, PROC_PIDTASKINFO_SIZE) <
      PROC_PIDTASKINFO_SIZE) {
    LOGW(@"Unable to get system resource information");
    return std::nullopt;
  }

  return SantaTaskInfo{
    .virtual_size = pti.pti_virtual_size,
    .resident_size = pti.pti_resident_size,
    .total_user_nanos = MachTimeToNanos(pti.pti_total_user),
    .total_system_nanos = MachTimeToNanos(pti.pti_total_system),
  };
}
