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

#include <stdint.h>
#include <sys/cdefs.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

#include "Source/common/SNTCommon.h"

/**
  A type to specialize to help SantaCache with its hashing.

  The default works for numeric types with a multiplicative hash
  using a prime near to the golden ratio, per Knuth.
*/
template <typename T>
uint64_t SantaCacheHasher(T const &t) {
  return (uint64_t)t * 11400714819323198549UL;
};

/**
  A somewhat simple, concurrent linked-list hash table intended for use in IOKit
  kernel extensions.

  The type used for keys must overload the == operator and a specialization of
  SantaCacheHasher must exist for it.

  Enforces a maximum size by clearing all entries if a new value
  is added that would go over the maximum size declared at creation.

  The number of buckets is calculated as `maximum_size` / `per_bucket`
  rounded up to the next power of 2. Locking is done per-bucket.
*/
template <typename KeyT, typename ValueT>
class SantaCache {
 public:
  /**
    Initialize a newly created cache.

    @param maximum_size The maximum number of entries in this cache. Once this
        number is reached all the entries will be purged.
    @param per_bucket The target number of entries in each bucket when cache is
    full. A higher number will result in better performance but higher memory
    usage. Cannot be higher than 64 to try and ensure buckets don't overflow.
  */
  SantaCache(uint64_t maximum_size = 10000, uint8_t per_bucket = 5) {
    if (unlikely(per_bucket > maximum_size)) per_bucket = (uint8_t)maximum_size;
    if (unlikely(per_bucket < 1)) per_bucket = 1;
    if (unlikely(per_bucket > 64)) per_bucket = 64;
    max_size_ = maximum_size;
    bucket_count_ =
        (1 << (32 -
               __builtin_clz((((uint32_t)max_size_ / per_bucket) - 1) ?: 1)));
    if (unlikely(bucket_count_ > UINT32_MAX)) bucket_count_ = UINT32_MAX;
    buckets_ = std::unique_ptr<struct bucket[]>(new bucket[bucket_count_]);
  }

  /**
    Get an element from the cache. Returns zero_ if item doesn't exist.
  */
  ValueT get(KeyT key) {
    struct bucket *bucket = &buckets_[hash(key)];
    bucket->lock();
    struct entry *entry = (struct entry *)((uintptr_t)bucket->head);
    while (entry != nullptr) {
      if (entry->key == key) {
        ValueT val = entry->value;
        bucket->unlock();
        return val;
      }
      entry = entry->next;
    }
    bucket->unlock();
    return zero_;
  }

  /**
    Set an element in the cache.

    @note If the cache is full when this is called, this will
        empty the cache before inserting the new value.

    @param key The key.
    @param value The value with parameterized type.

    @return true if the value was set.
  */
  bool set(const KeyT &key, const ValueT &value) {
    return set(key, value, {}, false);
  }

  /**
    Set an element in the cache.

    @note If the cache is full when this is called, this will
        empty the cache before inserting the new value.

    @param key The key.
    @param value The value with parameterized type.
    @param previous_value the new value will only be set if this
        parameter is equal to the existing value in the cache.
        This allows set to become a CAS operation.

    @return true if the value was set
  */
  bool set(const KeyT &key, const ValueT &value, const ValueT &previous_value) {
    return set(key, value, previous_value, true);
  }

  /**
    An alias for `set(key, zero_)`
  */
  inline void remove(const KeyT &key) { set(key, zero_); }

  /**
    Remove all entries and free bucket memory.
  */
  void clear() {
    for (uint32_t i = 0; i < bucket_count_; ++i) {
      struct bucket *bucket = &buckets_[i];
      // We grab the lock so nothing can use this bucket while we're erasing it.
      bucket->lock();

      // Free the bucket's entries, if there are any.
      struct entry *entry = (struct entry *)((uintptr_t)bucket->head);
      while (entry != nullptr) {
        struct entry *next_entry = entry->next;
        delete entry;
        entry = next_entry;
      }
    }

    // Reset cache count.
    count_ = 0;

    // Unlock all the buckets.
    for (uint32_t i = 0; i < bucket_count_; ++i) (&buckets_[i])->unlock();
  }

  /**
    Return number of entries currently in cache.
  */
  inline uint64_t count() const { return count_; }

  /**
    Fill in the per_bucket_counts array with the number of entries in each
    bucket.

    The per_buckets_count array will contain the per-bucket counts, up to the
    number in array_size. The start_bucket parameter will determine which bucket
    to start off with and upon return will contain either 0 if no buckets are
    remaining or the next bucket to begin with when called again.
  */
  void bucket_counts(uint16_t *per_bucket_counts, uint16_t *array_size,
                     uint64_t *start_bucket) {
    if (per_bucket_counts == nullptr || array_size == nullptr ||
        start_bucket == nullptr)
      return;

    uint64_t start = *start_bucket;
    if (start >= bucket_count_) {
      *start_bucket = 0;
      return;
    }

    uint16_t size = *array_size;
    if (start + size > bucket_count_) size = (uint16_t)(bucket_count_ - start);

    for (uint16_t i = 0; i < size; ++i) {
      uint16_t count = 0;
      struct bucket *bucket = &buckets_[start++];
      bucket->lock();
      struct entry *entry = (struct entry *)((uintptr_t)bucket->head);
      while (entry != nullptr) {
        if (entry->value != zero_) ++count;
        entry = entry->next;
      }
      bucket->unlock();
      per_bucket_counts[i] = count;
    }

    *array_size = size;
    *start_bucket = (start >= bucket_count_) ? 0 : start;
  }

 private:
  struct entry {
    KeyT key = {};
    ValueT value = {};
    struct entry *next = nullptr;
  };

  struct bucket {
    std::atomic_flag lock_ = ATOMIC_FLAG_INIT;

    struct entry *head = nullptr;

    // Lock this bucket. Will loop until it is successfully locked.
    void lock() {
      while (lock_.test_and_set());
    }

    // Unlock this bucket.
    void unlock() {
      lock_.clear();
    }
  };


  /**
    Set an element in the cache.

    @note If the cache is full when this is called, this will
    empty the cache before inserting the new value.

    @param key The key
    @param value The value with parameterized type
    @param previous_value If has_prev_value is true, the new value will only
        be set if this parameter is equal to the existing value in the cache.
        This allows set to become a CAS operation.
    @param has_prev_value Pass true if previous_value should be used.

    @return true if the entry was set, false if it was not
  */
  bool set(const KeyT &key, const ValueT &value, const ValueT &previous_value,
           bool has_prev_value) {
    struct bucket *bucket = &buckets_[hash(key)];
    bucket->lock();
    struct entry *entry = (struct entry *)((uintptr_t)bucket->head);
    struct entry *previous_entry = nullptr;
    while (entry != nullptr) {
      if (entry->key == key) {
        ValueT existing_value = entry->value;

        if (has_prev_value && previous_value != existing_value) {
          bucket->unlock();
          return false;
        }

        entry->value = value;

        if (value == zero_) {
          if (previous_entry != nullptr) {
            previous_entry->next = entry->next;
          } else {
            bucket->head = (struct entry *)((uintptr_t)entry->next);
          }
          delete entry;
          count_--;
        }

        bucket->unlock();
        return true;
      }
      previous_entry = entry;
      entry = entry->next;
    }

    // If value is zero_, we're clearing but there's nothing to clear
    // so we don't need to do anything else. Alternatively, if has_prev_value
    // is true and is not zero_ we don't want to set a value.
    if (value == zero_ || (has_prev_value && previous_value != zero_)) {
      bucket->unlock();
      return false;
    }

    // Check that adding this new item won't take the cache
    // over its maximum size.
    if (count_ + 1 > max_size_) {
      bucket->unlock();
      clear_bucket_.lock();
      // Check again in case clear has already run while waiting for lock
      if (count_ + 1 > max_size_) {
        clear();
      }
      bucket->lock();
      clear_bucket_.unlock();
    }

    // Allocate a new entry, set the key and value, then put this new entry at
    // the head of this bucket's linked list.
    struct entry *new_entry = new struct entry();
    new_entry->key = key;
    new_entry->value = value;
    new_entry->next = (struct entry *)((uintptr_t)bucket->head);
    bucket->head = (struct entry *)((uintptr_t)new_entry);
    count_++;

    bucket->unlock();
    return true;
  }

  std::atomic<uint_fast64_t> count_{0};

  uint64_t max_size_;
  uint32_t bucket_count_;

  std::unique_ptr<struct bucket[]> buckets_;

  /**
    Holder for a 'zero' entry for the current type
  */
  const ValueT zero_ = {};

  /**
    Special bucket used when automatically clearing due to size
    to prevent two threads trying to clear at the same time and
    getting stuck.
  */
  struct bucket clear_bucket_ = {};

  /**
    Hash a key to determine which bucket it belongs in.
  */
  inline uint64_t hash(KeyT input) const {
    return SantaCacheHasher<KeyT>(input) % bucket_count_;
  }
};

#endif  // SANTA__SANTA_DRIVER__SANTACACHE_H
