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

// Declarations for the macOS platform expert layer.
// The CircularQueue code is cross-platform. To be able to build on Linux and in
// userspace, it uses a set of abstract declarations for allocations, locks,
// and similar platform-specific functionality.

#ifndef SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_PLATFORM_EXPERT_H
#define SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_PLATFORM_EXPERT_H

#include "QueueTypes.h"
#include <libkern/OSAtomic.h>

// Allocates kernel memory - doesn't block.
helm_buffer_t helm_xalloc(size_t);
void helm_xfree(helm_buffer_t);

// Spinlocks are a primitive locking construct that keeps running in a loop,
// until it has acquired the lock. They are used in low-level code where
// yielding the CPU (which is what mutexes and sleeplocks do) is impractical or
// dangerous. The common implementations in kernels also disable interrupts.
//
// In the userland (for tests) the below can be implemented using mutexes.
//
// For more information:
// https://www.kernel.org/doc/Documentation/locking/spinlocks.txt
void helm_spin_init(helm_spinlock_t *l);
void helm_spin_destroy(helm_spinlock_t *l);
void helm_spin_lock(helm_spinlock_t *l, helm_irql_t *irql);
void helm_spin_unlock(helm_spinlock_t *l, helm_irql_t *irql);

// Mutexes are locks that yield the CPU until the lock is available (this is
// done by the executing thread giving up its remaining time quantum). They are
// used in places where the mutually-exclusive code section can take a long time
// and yielding the CPU is not a problem (this is almost always true in userland
// code).
void helm_mutex_init(helm_mutex_t *l);
void helm_mutex_destroy(helm_mutex_t *l);
void helm_mutex_unlock(helm_mutex_t *l);
void helm_mutex_lock(helm_mutex_t *l);

#define HELM_ATOMIC_LITERAL(val) (val)
#define helm_atomic_get(atom) *(atom)

static inline int64_t helm_atomic_cmp_swap(helm_atomic_t *atom, int64_t ov,
                                           int64_t nv) {
    // For whatever reason, OSCompareAndSwap64 uses unsigned ints as arguments,
    // even when the rest of OSAtomic works with signed ints. It's just bytes,
    // however - the below pointer cast is ugly but it does get the job done.
    
    uint64_t ov_ = *(uint64_t *)&ov;  // NOLINT(readability/casting)
    uint64_t nv_ = *(uint64_t *)&nv;  // NOLINT(readability/casting)
    if (OSCompareAndSwap64(ov_, nv_, atom)) {
        return ov;
    }
    
    return 0;
}

static inline void helm_bzero(void *buffer, size_t size) {
    bzero(buffer, size);
}

#ifdef NDEBUG
#define helm_debug(fmt, ...)
#else
#define helm_debug(fmt, ...) printf("D " fmt "\n", ##__VA_ARGS__)
#endif

#define helm_info(fmt, ...) printf("I " fmt "\n", ##__VA_ARGS__)
#define helm_warn(fmt, ...) printf("W " fmt "\n", ##__VA_ARGS__)
#define helm_error(fmt, ...) printf("E "  fmt "\n", ##__VA_ARGS__)
#define helm_fatal(fmt, ...) printf("F " fmt "\n", ##__VA_ARGS__)

void helm_panic(const char *reason);

static inline void __HELM_BUG_ON(int cond, const char *reason) {
    if (cond) {
        helm_panic(reason);
    }
}

// Panic if 'cond' occurs. Used only for things that should never ever happen.
// When built for the drivers outside of testing, it may be reasonable to
// disable this macro.
#define HELM_BUG_ON(cond, reason) __HELM_BUG_ON((int)(cond), (reason))

#endif  // SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_PLATFORM_EXPERT_H