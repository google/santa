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

#include "QueuePlatformExpert.h"
#include <libkern/OSMalloc.h>
#include <string.h>

void helm_spin_init(helm_spinlock_t *l) {
    l->lck_grp_attr = lck_grp_attr_alloc_init();
    lck_grp_attr_setstat(l->lck_grp_attr);
    l->lck_grp = lck_grp_alloc_init("helm spinlocks", l->lck_grp_attr);
    l->lck_attr = lck_attr_alloc_init();
    l->lck = lck_spin_alloc_init(l->lck_grp, l->lck_attr);
}

void helm_spin_destroy(helm_spinlock_t *l) {
    lck_spin_free(l->lck, l->lck_grp);
    lck_attr_free(l->lck_attr);
    lck_grp_free(l->lck_grp);
    lck_grp_attr_free(l->lck_grp_attr);
}

void helm_spin_lock(helm_spinlock_t *l, helm_irql_t *irql) { lck_spin_lock(l->lck); }

void helm_spin_unlock(helm_spinlock_t *l, helm_irql_t *irql) { lck_spin_unlock(l->lck); }

void helm_mutex_init(helm_mutex_t *l) {
    l->lck_grp_attr = lck_grp_attr_alloc_init();
    lck_grp_attr_setstat(l->lck_grp_attr);
    l->lck_grp = lck_grp_alloc_init("helm mutexes", l->lck_grp_attr);
    l->lck_attr = lck_attr_alloc_init();
    l->lck = lck_mtx_alloc_init(l->lck_grp, l->lck_attr);
}

void helm_mutex_destroy(helm_mutex_t *l) {
    lck_mtx_free(l->lck, l->lck_grp);
    lck_attr_free(l->lck_attr);
    lck_grp_free(l->lck_grp);
    lck_grp_attr_free(l->lck_grp_attr);
}

void helm_mutex_lock(helm_mutex_t *l) { lck_mtx_lock(l->lck); }

void helm_mutex_unlock(helm_mutex_t *l) { lck_mtx_unlock(l->lck); }

// XNU-specific malloc implementation.
//
// OSMalloc (Mach's allocation routines) is the preferred API to allocate
// memory outside of IOKit. It is likely to eventually replace vm_allocate as
// the only C-visible API linked by kxld.
//
// This does have a few caveats:
//
// 1) The caller has to keep track of allocation size, and pass it to OSFree.
// This is why helm_buffer_t on XNU is 12 bytes wide.
//
// 2) The effective width of the size type is 32 bits.
//
// 3) A shared tag must be initialized before any calls to OSMalloc.

// This extern MUST be initialized by the kext init function before first alloc.
extern OSMallocTag_t helm_shared_tag;

helm_buffer_t helm_xalloc(size_t size) {
    helm_buffer_t ret;
    bzero(&ret, sizeof(helm_buffer_t));
    
    if ((uint32_t)size < size) {
        return ret;
    }
    
    ret.ptr = OSMalloc((uint32_t)size, helm_shared_tag);
    if (!ret.ptr) {
        return ret;
    }
    
    ret.size = (uint32_t)size;
    
    return ret;
}

void helm_xfree(helm_buffer_t buffer) {
    OSFree(buffer.ptr, buffer.size, helm_shared_tag);
}

// XNU doesn't have a good way for a kext to crash without taking down the
// whole system. Forcing a panic in non-debug mode might be too extreme, so we
// just continue and hope the platform-specific code knows how to shut down
// gracefully.
void helm_panic(const char *reason) {
    helm_fatal("fatal error: %s", reason);
}
