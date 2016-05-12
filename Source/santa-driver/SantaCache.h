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

#define likely(x)   __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

#ifdef KERNEL
#include <IOKit/IOLib.h>
#else // KERNEL
// Support for unit testing.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#define panic(args...) printf(args); printf("\n"); abort()
#define IOMalloc malloc
#define IOFree(addr, sz) (void)(sz); free(addr)
#define OSTestAndSet OSAtomicTestAndSet
#define OSTestAndClear(bit, addr) OSAtomicTestAndClear(bit, addr) == 0
#define OSIncrementAtomic(addr) OSAtomicIncrement64((volatile int64_t *)addr)
#define OSDecrementAtomic(addr) OSAtomicDecrement64((volatile int64_t *)addr)
#endif // KERNEL

/**
  A somewhat simple, concurrent array hash table implementation intended for use
  in IOKit kernel extensions. Maps 64-bit unsigned integer keys to values.
 
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
    @param per_bucket The maximum number of entries in each bucket. A higher
        number will result in better performance but higher memory usage.
        Cannot be higher than 126 due to type requirements.
  */
  SantaCache(uint64_t maximum_size = 10000, uint8_t per_bucket = 5) {
    if (unlikely(per_bucket > 126)) per_bucket = 126;
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
    struct bucket *bucket = &buckets_[hash(key) % bucket_count_];
    lock(bucket);
    for (int i = 0; i < bucket_count(bucket); ++i) {
      struct entry *entry = &bucket->entry[i];

      if (entry->key == key) {
        unlock(bucket);
        return entry->value;
      }
    }
    unlock(bucket);
    return zero_;
  }

  /**
    Set an element in the cache.
   
    @return if an existing value was replaced, the previous value, otherwise zero_
  */
  T set(uint64_t key, T value) {
    struct bucket *bucket = &buckets_[hash(key) % bucket_count_];
    lock(bucket);
    for (int i = 0; i < bucket_count(bucket); ++i) {
      struct entry *entry = &bucket->entry[i];

      if (entry->key == key) {
        // Found existing key, replace value.
        T existing_value = entry->value;
        entry->value = value;

        if (value == zero_) {
          bucket_shrink(bucket, i);
        }

        unlock(bucket);
        return existing_value;
      }
    }

    // If value is zero_, we're clearing but there's nothing to clear
    // so we don't need to do anything else.
    if (value == zero_) {
      unlock(bucket);
      return zero_;
    }

    // Check that adding this new item won't take the cache over its
    // maximum size.
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

    // We didn't find the entry in the bucket, so grow the bucket
    // and add the new entry at the beginning.
    bucket_grow(bucket);
    bucket->entry->key = key;
    bucket->entry->value = value;
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
    for (int i = 0; i < bucket_count_; ++i) {
      struct bucket *bucket = &buckets_[i];
      // We grab the lock so nothing can use this bucket while we're erasing it
      // and never release it. It'll be 'released' when the bzero call happens
      // at the end of this function.
      lock(bucket);

      // Free the bucket's entries, if there are any.
      if (bucket->entry) {
        size_t free_size = bucket_count(bucket) * sizeof(struct entry);
        IOFree(bucket->entry, free_size);
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
  };

  struct bucket {
    struct entry *entry;
    // The top bit of this value is the lock,
    // the remaining 7 bits are the count.
    uint8_t count_and_lock;
  };

  /**
    Return the number of items in a bucket
  */
  inline uint8_t bucket_count(struct bucket *bucket) const {
    return bucket->count_and_lock & ~0x80;
  }

  /**
    Lock a bucket. Spins until the lock is acquired.
  */
  inline void lock(struct bucket *bucket) const {
    while (OSTestAndSet(0, &bucket->count_and_lock));
  }

  /**
    Unlock a bucket. Panics if the lock wasn't locked.
  */
  inline void unlock(struct bucket *bucket) const {
    if (unlikely(OSTestAndClear(0, &bucket->count_and_lock))) {
      panic("SantaCache::unlock(): Tried to unlock an unlocked lock");
    }
  }

  uint64_t count_;
  uint64_t max_size_;

  uint32_t bucket_count_;
  struct bucket *buckets_;

  /**
    Holder for a 'zero' entry for the current type
  */
  T zero_ = {};

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
    return (input * 11400714819323198549ul);
  }

  /**
    Grow a given bucket by 1 entry.
  
    @note The lock for this bucket must already be held.
   
    @param bucket, The bucket to grow.
  */
  void bucket_grow(struct bucket *bucket) {
    uint32_t current_size = bucket_count(bucket);
    bucket->count_and_lock++;
    OSIncrementAtomic(&count_);
    size_t alloc_size = bucket_count(bucket) * sizeof(struct entry);
    struct entry *entry_list = (struct entry *)IOMalloc(alloc_size);
    bzero(entry_list, alloc_size);
    bcopy(bucket->entry, entry_list + 1, current_size * sizeof(struct entry));
    IOFree(bucket->entry, current_size * sizeof(struct entry));
    bucket->entry = entry_list;
  }

  /**
    Shrink a bucket by 1 entry.

    @note The lock for this bucket must already be held.
   
    @param bucket, The bucket to shrink.
    @param idx, The 0-based index in the bucket to remove.
  */
  void bucket_shrink(struct bucket *bucket, int idx) {
    size_t alloc_size = (bucket_count(bucket) - 1) * sizeof(struct entry);
    struct entry *entry_list = (struct entry *)IOMalloc(alloc_size);
    bzero(entry_list, alloc_size);

    uint32_t after = bucket_count(bucket) - idx - 1;
    uint32_t before = bucket_count(bucket) - after - 1;

    bcopy(bucket->entry, entry_list, before * sizeof(struct entry));
    bcopy(&bucket->entry[idx + 1],
          &entry_list[before],
          after * sizeof(struct entry));

    IOFree(bucket->entry, bucket_count(bucket) * sizeof(struct entry));

    bucket->count_and_lock--;
    OSDecrementAtomic(&count_);
    bucket->entry = entry_list;
  }
};

#endif // SANTA__SANTA_DRIVER__SANTACACHE_H
