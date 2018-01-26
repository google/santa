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

// Cross-platform atomic operations.

#ifndef SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_ATOMIC_H
#define SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_ATOMIC_H

#include "QueuePlatformExpert.h"

// A safe version of helm_atomic_inc, which wraps the atom to 'init' if it would
// exceed INT64_MAX.
//
// Note that most modern architectures would wrap to INT64_MIN anyway, but,
// strictly speaking, that behavior is undefined by the C standard.
static inline int64_t helm_atomic_inc_wrap(helm_atomic_t *atom, int64_t init) {
    int64_t v, nv;
    
    do {
        v = helm_atomic_get(atom);
        
        if (v == INT64_MAX) {
            nv = init;
        } else {
            nv = v + 1;
        }
    } while (helm_atomic_cmp_swap(atom, v, nv) != v);
    
    return nv;
}

// Safely and atomically adds 'delta' to the value of 'atom', capping the values
// at INT64_MAX and INT64_MIN if they would overflow or underflow, respectively.
//
// This is useful for reporting totals (e.g. for performance) where very large
// absolute values have meaning and wrapping is not desirable.
static inline int64_t helm_atomic_add_cap(helm_atomic_t *atom, int64_t delta) {
    int64_t v, nv;
    
    do {
        v = helm_atomic_get(atom);
        if (delta > 0 && INT64_MAX - delta < v) {  // Overflow.
            nv = INT64_MAX;
        } else if (delta < 0 && INT64_MIN - delta > v) {  // Underflow.
            nv = INT64_MIN;
        } else {
            nv = v + delta;
        }
    } while (helm_atomic_cmp_swap(atom, v, nv) != v);
    
    return nv;
}

// Resets an atomic counter to zero and returns the latest value.
static inline int64_t helm_atomic_reset(helm_atomic_t *atom) {
    int64_t v;
    
    do {
        v = helm_atomic_get(atom);
    } while (helm_atomic_cmp_swap(atom, v, 0) != v);
    
    return v;
}

#endif  // SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_ATOMIC_H