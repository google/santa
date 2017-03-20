/// Copyright 2016 Google Inc. All rights reserved.
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

#ifndef SANTA__SANTA_DRIVER__SANTACACHE_H
#define SANTA__SANTA_DRIVER__SANTACACHE_H

#include <libkern/OSAtomic.h>
#include <libkern/OSTypes.h>
#include <stdint.h>
#include <sys/cdefs.h>

#include "SNTKernelCommon.h"

#ifdef KERNEL
#include <IOKit/IOLib.h>
#else // KERNEL
// Support for unit testing.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#define panic(args...) printf(args); printf("\n"); abort()
#define IOMalloc malloc
#define IOMallocAligned(sz, alignment) malloc(sz);
#define IOFree(addr, sz) free(addr)
#define IOFreeAligned(addr, sz) free(addr)
#define OSTestAndSet OSAtomicTestAndSet
#define OSTestAndClear(bit, addr) OSAtomicTestAndClear(bit, addr) == 0
#define OSIncrementAtomic(addr) OSAtomicIncrement64((volatile int64_t *)addr)
#define OSDecrementAtomic(addr) OSAtomicDecrement64((volatile int64_t *)addr)
#endif // KERNEL

/**
  A somewhat simple, concurrent linked-list hash table intended for use in IOKit kernel extensions.
  Maps 64-bit unsigned integer keys to values.

  Enforces a maximum size by clearing all entries if a new value
  is added that would go over the maximum size declared at creation.

  The number of buckets is calculated as `maximum_size` / `per_bucket`
  rounded up to the next power of 2. Locking is done per-bucket.
*/
template<class T> class SantaCache {
 public:
  /**
    Initialize a newly created cache.

    @param maximum_size The maximum number of entries in this cache. Once this
        number is reached all the entries will be purged.
    @param per_bucket The target number of entries in each bucket when cache is full.
        A higher number will result in better performance but higher memory usage.
        Cannot be higher than 64 to try and ensure buckets don't overflow.
  */
  SantaCache(uint64_t maximum_size = 10000, uint8_t per_bucket = 5) {
    if (unlikely(per_bucket < 1)) per_bucket = 1;
    if (unlikely(per_bucket > 64)) per_bucket = 64;
    max_size_ = maximum_size;
    bucket_count_ = 1 << (32 - __builtin_clz(
        ((uint32_t)max_size_ / per_bucket) - 1));
    buckets_ = (struct bucket *)IOMalloc(bucket_count_ * sizeof(struct bucket));
    bzero(buckets_, bucket_count_ * sizeof(struct bucket));
  }

  /**
    Clear and free memory
  */
  ~SantaCache() {
    clear();
    IOFree(buckets_, bucket_count_ * sizeof(struct bucket));
  }

  /**
    Get an element from the cache. Returns zero_ if item doesn't exist.
  */
  T get(uint64_t key) {
    struct bucket *bucket = &buckets_[hash(key)];
    lock(bucket);
    struct entry *entry = (struct entry *)((uintptr_t)bucket->head - 1);
    while (entry != nullptr) {
      if (entry->key == key) {
        T val = entry->value;
        unlock(bucket);
        return val;
      }
      entry = entry->next;
    }
    unlock(bucket);
    return zero_;
  }

  /**
    Set an element in the cache.

    @note If the cache is full when this is called, this will empty the cache before
    inserting the new value.

    @return if an existing value was replaced, the previous value, otherwise zero_
  */
  T set(uint64_t key, T value) {
    struct bucket *bucket = &buckets_[hash(key)];
    lock(bucket);
    struct entry *entry = (struct entry *)((uintptr_t)bucket->head - 1);
    struct entry *previous_entry = nullptr;
    while (entry != nullptr) {
      if (entry->key == key) {
        T existing_value = entry->value;
        entry->value = value;

        if (value == zero_) {
          if (previous_entry != nullptr) {
            previous_entry->next = entry->next;
          } else {
            bucket->head = (struct entry *)((uintptr_t)entry->next + 1);
          }
          IOFreeAligned(entry, sizeof(struct entry));
          OSDecrementAtomic(&count_);
        }

        unlock(bucket);
        return existing_value;
      }
      previous_entry = entry;
      entry = entry->next;
    }

    // If value is zero_, we're clearing but there's nothing to clear
    // so we don't need to do anything else.
    if (value == zero_) {
      unlock(bucket);
      return zero_;
    }

    // Check that adding this new item won't take the cache over its maximum size.
    if (count_ + 1 > max_size_) {
      unlock(bucket);
      lock(&clear_bucket_);
      // Check again in case clear has already run while waiting for lock
      if (count_ + 1 > max_size_) {
        clear();
      }
      lock(bucket);
      unlock(&clear_bucket_);
    }

    // Allocate a new entry, set the key and value, then set the next pointer as the current
    // first entry in the bucket then make this new entry the first in the bucket.
    struct entry *new_entry = (struct entry *)IOMallocAligned(sizeof(struct entry), 2);
    new_entry->key = key;
    new_entry->value = value;
    new_entry->next = (struct entry *)((uintptr_t)bucket->head - 1);
    bucket->head = (struct entry *)((uintptr_t)new_entry + 1);
    OSIncrementAtomic(&count_);

    unlock(bucket);
    return zero_;
  }

  /**
    An alias for `set(key, zero_)`
  */
  inline void remove(uint64_t key) {
    set(key, zero_);
  }

  /**
    Remove all entries and free bucket memory.
  */
  void clear() {
    for (uint32_t i = 0; i < bucket_count_; ++i) {
      struct bucket *bucket = &buckets_[i];
      // We grab the lock so nothing can use this bucket while we're erasing it
      // and never release it. It'll be 'released' when the bzero call happens
      // at the end of this function.
      lock(bucket);

      // Free the bucket's entries, if there are any.
      struct entry *entry = (struct entry *)((uintptr_t)bucket->head - 1);
      while (entry != nullptr) {
        struct entry *next_entry = entry->next;
        IOFreeAligned(entry, sizeof(struct entry));
        entry = next_entry;
      }
    }

    // Reset cache count, no atomicity needed as we hold all the bucket locks.
    count_ = 0;

    // This resets all of the bucket counts and locks. Releasing the locks for
    // each bucket isn't really atomic here but each bucket will be zero'd
    // before the lock is released as the lock is the last thing in a bucket.
    bzero(buckets_, bucket_count_ * sizeof(struct bucket));
  }

  /**
    Return number of entries currently in cache.
  */
  inline uint64_t count() const {
    return count_;
  }

 private:
  struct entry {
    uint64_t key;
    T value;
    struct entry *next;
  };

  struct bucket {
    // The least significant bit of this pointer is always 0 (due to alignment),
    // so we utilize that bit as the lock for the bucket.
    struct entry *head;
  };

  /**
    Lock a bucket. Spins until the lock is acquired.
  */
  inline void lock(struct bucket *bucket) const {
    while (OSTestAndSet(7, (volatile uint8_t *)&bucket->head));
  }

  /**
    Unlock a bucket. Panics if the lock wasn't locked.
  */
  inline void unlock(struct bucket *bucket) const {
    if (unlikely(OSTestAndClear(7, (volatile uint8_t *)&bucket->head))) {
      panic("SantaCache::unlock(): Tried to unlock an unlocked lock");
    }
  }

  uint64_t count_ = 0;

  uint64_t max_size_;
  uint32_t bucket_count_;

  struct bucket *buckets_;

  /**
    Holder for a 'zero' entry for the current type
  */
  const T zero_ = T(0);

  /**
    Special bucket used when automatically clearing due to size
    to prevent two threads trying to clear at the same time and
    getting stuck.
  */
  struct bucket clear_bucket_ = {};

  /**
    Hash a key to determine which bucket it belongs in.

    Multiplicative hash using a prime near to the golden ratio, per Knuth.
    This seems to have good bucket distribution generally and for the range of
    values we expect to see.
  */
  inline uint64_t hash(uint64_t input) const {
    return (input * 11400714819323198549ul) % bucket_count_;
  }
};

#endif // SANTA__SANTA_DRIVER__SANTACACHE_H
