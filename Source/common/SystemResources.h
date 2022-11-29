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

#ifndef SANTA__COMMON__SYSTEMRESOURCES_H
#define SANTA__COMMON__SYSTEMRESOURCES_H

#import <Foundation/Foundation.h>
#include <mach/mach_time.h>
#include <sys/cdefs.h>
#include <sys/proc_info.h>

__BEGIN_DECLS

// Convert mach absolute time to nanoseconds
uint64_t MachTimeToNanos(uint64_t mach_time);

// Convert nanoseconds to mach absolute time
uint64_t NanosToMachTime(uint64_t nanos);

// Get the result of proc_pidinfo with the PROC_PIDTASKINFO flavor
BOOL GetTaskInfo(struct proc_taskinfo *pti_out);

__END_DECLS

#endif
