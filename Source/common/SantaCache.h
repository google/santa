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

#ifndef SANTA__SANTA_DRIVER__SANTACACHE_H
#define SANTA__SANTA_DRIVER__SANTACACHE_H

#include <libkern/OSAtomic.h>
#include <libkern/OSTypes.h>
#include <os/log.h>
#include <stdint.h>
#include <sys/cdefs.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_map>

#include "Source/common/SNTCommon.h"
#include "absl/synchronization/mutex.h"

/**
  A simple cache built on top of an std::unordered_map

  The type used for keys must provide a specialized std::hash template
  for the key type and overload `operator()`.

  Enforces a maximum size by clearing all entries if a new value
  is added that would go over the maximum size declared at creation.
*/
template <typename KeyT, typename ValueT>
class SantaCache {
 public:
  /**
    Initialize a newly created cache.

    @param maximum_size The maximum number of entries in this cache. Once this
        number is reached all the entries will be purged.
  */
  SantaCache(uint64_t maximum_size = 10000)
      : max_size_(maximum_size) {}

  /**
    Clear and free memory
  */
  ~SantaCache() { Clear(); }

  /**
    Get an element from the cache. Returns zero_ if item doesn't exist.
  */
  ValueT Get(KeyT key) {
    absl::ReaderMutexLock lock(&lock_);

    const auto iter = cache_.find(key);
    if (iter != cache_.end()) {
      return iter->second;
    } else {
      return zero_;
    }
  }

  /**
    Set an element in the cache.

    @note If the cache is full when this is called, this will
        empty the cache before inserting the new value.

    @param key The key.
    @param value The value with parameterized type.

    @return true if the value was set.
  */
  bool Set(const KeyT &key, const ValueT &value) {
    absl::MutexLock lock(&lock_);
    return SetLocked(key, value, {}, false);
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
  bool Set(const KeyT &key, const ValueT &value, const ValueT &previous_value) {
    absl::MutexLock lock(&lock_);
    return SetLocked(key, value, previous_value, true);
  }

  /**
    Remove a key from the cache
  */
  inline void Remove(const KeyT &key) {
    absl::MutexLock lock(&lock_);
    RemoveLocked(key);
  }

  /**
    Remove all entries
  */
  void Clear() {
    absl::MutexLock lock(&lock_);
    ClearLocked();
  }

  /**
    Return number of entries currently in cache.
  */
  uint64_t Count() const {
    absl::ReaderMutexLock lock(&lock_);
    return CountLocked();
  }

 private:
  ABSL_SHARED_LOCKS_REQUIRED(lock_)
  uint64_t CountLocked() const {
    return cache_.size();
  }

  ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_)
  void ClearLocked() { cache_.clear(); }

  ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_)
  void RemoveLocked(const KeyT &key) { cache_.erase(key); }

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
  ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_)
  bool SetLocked(const KeyT &key, const ValueT &value, const ValueT &previous_value,
           bool has_prev_value) {
    const auto iter = cache_.find(key);

    if (has_prev_value) {
      if ((iter != cache_.end() && previous_value != iter->second) ||
          (iter == cache_.end() && previous_value != zero_)) {
        // Existing value didn't match expected (or there was no existing value
        // and the expected previous value wasn't the zero_ value)
        return false;
      }
    }

    if (value == zero_) {
      // Setting to the zero_ value removes the element by definition
      RemoveLocked(key);
      return true;
    }

    uint64_t new_size = CountLocked();
    if (iter == cache_.end()) {
      // If this key didn't previously exist, we'll be growing the
      // size of the cache
      new_size += 1;
    }

    if (new_size > max_size_) {
      ClearLocked();
    }

    cache_.insert_or_assign(key, value);
    return true;
  }

  uint64_t max_size_;
  std::unordered_map<KeyT, ValueT> cache_;
  mutable absl::Mutex lock_;

  /**
    Holder for a 'zero' entry for the current type
  */
  const ValueT zero_ = {};
};

#endif  // SANTA__SANTA_DRIVER__SANTACACHE_H
