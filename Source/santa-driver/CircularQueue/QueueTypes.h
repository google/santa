// Copyright 2017 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

#ifndef SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_TYPES_H
#define SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_TYPES_H

#include <libkern/libkern.h>
#include <libkern/locks.h>
#include <mach/mach_types.h>
#include <sys/errno.h>

// The authors are aware of kern_return_t, but the number of different return
// code conventions in use by the XNU codebase renders pointless any attempt by
// the HELM to use native error codes the same way we do on Linux.
typedef int helm_return_t;

// XNU uses lock groups and related structures mainly for lock tracing and
// debugging. Use of these additional structures is mandatory; though they can
// be allocated once and shared by multiple locks, we allocate new ones every
// time to make the lifecycle code simpler.
typedef struct {
    lck_grp_attr_t *lck_grp_attr;
    lck_grp_t *lck_grp;
    lck_attr_t *lck_attr;
    lck_spin_t *lck;
} helm_spinlock_t;

// TODO(adamsh): Investigate interruptibility semantics on XNU and decide
// whether it needs to handle different IRQ levels.
typedef int helm_irql_t;

// Mutexes on XNU need the same group structures as spinlocks.
typedef struct {
    lck_grp_attr_t *lck_grp_attr;
    lck_grp_t *lck_grp;
    lck_attr_t *lck_attr;
    lck_mtx_t *lck;
} helm_mutex_t;

// The Frankenstein's monster that is the XNU defines no fewer than three return
// code convetions. They are:
//  * osfmk/kern_return.h - Mach return code standard, notably used by the
//  kexts' init/exit functions.
//  * bsd/sys/errno.h - BSD standard, largely the same as return codes on Linux
//  and libc. Used in the IO system, and throughout.
//  * audit_bsm_errno.c - Solaris error codes - XNU borrows the Basic Security
//  Module from the Solaris kernel. Complete with a runtime conversion/lookup
//  table!
//
// The lack of method to XNU's madness is apparent in places like the chud
// device (chud_bsd_callback.c) whose functions return an int and combine the
// constants from kern_return.h and errno.h in the same function's image. This
// works, because kern_return_t is always typedef'd to int, and most of the Mach
// codebase really only cares about KERN_SUCCESS and KERN_FAILURE, whose literal
// values correspond to 0 and errno's EIO error, respectively.
//
// After due consideration, HELM is going with a similar convention - we will
// indicate general success with 0 (same as on Linux) and general failure with
// KERN_FAILURE/EIO (same as on Linux except the sign bit is flipped); we
// indicate other forms of failure with the appropriate errno.h codes.
#define HELM_SUCCESS KERN_SUCCESS
#define HELM_FAILURE KERN_FAILURE
#define HELM_EAGAIN EAGAIN
#define HELM_EINVAL EINVAL
#define HELM_EIO EIO

// Used to wrap around XNU's hairy allocation code.
typedef struct {
    void *ptr;
    
    // We need to keep record of allocated buffer size for OSFree. OSMalloc
    // uses a 32bit unsigned for size for some reason.
    uint32_t size;
} helm_buffer_t;

typedef int64_t helm_atomic_t;

// We used to borrow these from whatever platform we were building on, but they
// are always the same and the platforms kept moving them around, and the values
// never change so it seems easier to just declare our own.
#ifndef UINT8_MAX
#define UINT8_MAX ((uint8_t)(~0U))
#endif

#ifndef UINT16_MAX
#define UINT16_MAX ((uint16_t)(~0U))
#endif

#ifndef UINT32_MAX
#define UINT32_MAX ((uint32_t)(~0U))
#endif

#ifndef UINT64_MAX
#define UINT64_MAX ((uint64_t)(~0ULL))
#endif

#ifndef INT8_MAX
#define INT8_MAX ((int8_t)(UINT8_MAX >> 1))
#endif

#ifndef INT8_MIN
#define INT8_MIN ((int8_t)(-INT8_MAX - 1))
#endif

#ifndef INT16_MAX
#define INT16_MAX ((int16_t)(UINT16_MAX >> 1))
#endif

#ifndef INT16_MIN
#define INT16_MIN ((int16_t)(-INT16_MAX - 1))
#endif

#ifndef INT32_MAX
#define INT32_MAX ((int32_t)(UINT32_MAX >> 1))
#endif

#ifndef INT32_MIN
#define INT32_MIN ((int32_t)(-INT32_MAX - 1))
#endif

#ifndef INT64_MAX
#define INT64_MAX ((int64_t)(UINT64_MAX >> 1LL))
#endif

#ifndef INT64_MIN
#define INT64_MIN ((int64_t)(-INT64_MAX - 1))
#endif

#endif  // SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_TYPES_H