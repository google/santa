
/// Copyright 2022 Google Inc. All rights reserved.
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

#include "Source/santad/EventProviders/AuthResultCache.h"

#include <mach/clock_types.h>
#include <time.h>

#import "Source/common/SNTLogging.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Client;

// Santa currently only flushes caches when new DENY rules are added, not ALLOW
// rules. This means this value should be low enough so that if a previously
// denied binary is allowed, it can be re-executed by the user in a timely
// manner. But the value should be high enough to allow the cache to be
// effective in the event the binary is executed in rapid succession.
static const uint64_t kMaxCacheDenyTimeMilliseconds = 1500;

template <>
uint64_t SantaCacheHasher<santa_vnode_id_t>(santa_vnode_id_t const &t) {
  return (SantaCacheHasher<uint64_t>(t.fsid) << 1) ^ SantaCacheHasher<uint64_t>(t.fileid);
}

namespace santa::santad::event_providers {

static inline santa_vnode_id_t VnodeForFile(const es_file_t* es_file) {
  return santa_vnode_id_t{
    .fsid = (uint64_t)es_file->stat.st_dev,
    .fileid = es_file->stat.st_ino,
  };
}

static inline uint64_t GetCurrentUptime() {
  return clock_gettime_nsec_np(CLOCK_MONOTONIC);
}

// Decision is stored in upper 8 bits, timestamp in remaining 56.
static inline uint64_t CacheableAction(santa_action_t action,
                                       uint64_t timestamp = GetCurrentUptime()) {
  return ((uint64_t)action << 56) | (timestamp & 0xFFFFFFFFFFFFFF);
}

static inline santa_action_t ActionFromCachedValue(uint64_t cachedValue) {
  return (santa_action_t)(cachedValue >> 56);
}

static inline uint64_t TimestampFromCachedValue(uint64_t cachedValue) {
  return (cachedValue & ~(0xFF00000000000000));
}

AuthResultCache::AuthResultCache(std::shared_ptr<EndpointSecurityAPI> es_api)
    : es_api_(es_api) {
  root_cache_ = new SantaCache<santa_vnode_id_t, uint64_t>();
  nonroot_cache_ = new SantaCache<santa_vnode_id_t, uint64_t>();

  struct stat sb;
  if (stat("/", &sb) == 0) {
    root_devno_ = sb.st_dev;
  }

  q_ = dispatch_queue_create("com.google.santa.santad.auth_result_cache.q",
                             DISPATCH_QUEUE_SERIAL);
}

AuthResultCache::~AuthResultCache() {
  delete root_cache_;
  delete nonroot_cache_;
}

void AuthResultCache::AddToCache(const es_file_t *es_file,
                                 santa_action_t decision) {
  santa_vnode_id_t vnode_id = VnodeForFile(es_file);
  auto cache = CacheForVnodeID(vnode_id);
  switch (decision) {
    case ACTION_REQUEST_BINARY:
      cache->set(vnode_id, CacheableAction(ACTION_REQUEST_BINARY, 0), 0);
      break;
    case ACTION_RESPOND_ALLOW:
      OS_FALLTHROUGH;
    case ACTION_RESPOND_ALLOW_COMPILER:
      OS_FALLTHROUGH;
    case ACTION_RESPOND_DENY:
      cache->set(vnode_id,
                 CacheableAction(decision),
                 CacheableAction(ACTION_REQUEST_BINARY, 0));
      break;
    default:
      // This is a programming error. Bail.
      LOGE(@"Invalid cache value, exiting.");
      exit(EXIT_FAILURE);
  }
}

void AuthResultCache::RemoveFromCache(const es_file_t *es_file) {
  santa_vnode_id_t vnode_id = VnodeForFile(es_file);
  CacheForVnodeID(vnode_id)->remove(vnode_id);
}

santa_action_t AuthResultCache::CheckCache(const es_file_t *es_file) {
  return CheckCache(VnodeForFile(es_file));
}

santa_action_t AuthResultCache::CheckCache(santa_vnode_id_t vnode_id) {
  auto cache = CacheForVnodeID(vnode_id);

  uint64_t cached_val = cache->get(vnode_id);
  if (cached_val == 0) {
    return ACTION_UNSET;
  }

  santa_action_t result = ActionFromCachedValue(cached_val);


  if (result == ACTION_RESPOND_DENY) {
    auto expiry_time = TimestampFromCachedValue(cached_val) +
                       (kMaxCacheDenyTimeMilliseconds * NSEC_PER_MSEC);
    if (expiry_time < GetCurrentUptime()) {
      cache->remove(vnode_id);
      return ACTION_UNSET;
    }
  }

  return result;
}

SantaCache<santa_vnode_id_t, uint64_t>* AuthResultCache::CacheForVnodeID(
    santa_vnode_id_t vnode_id) {
  return (vnode_id.fsid == root_devno_ || root_devno_ == 0) ?
      root_cache_ :
      nonroot_cache_;
}

void AuthResultCache::FlushCache(FlushCacheMode mode) {
  nonroot_cache_->clear();
  if (mode == FlushCacheMode::kAllCaches) {
    root_cache_->clear();

    // Clear the ES cache when all local caches are flushed. Assume the ES cache
    // doesn't need to be cleared when only flushing the non-root cache.
    //
    // Calling into ES should be done asynchronously since it could otherwise
    // potentially deadlock

    auto shared_es_api = es_api_->shared_from_this();
    dispatch_async(q_, ^{
      // ES does not need a connected client to clear cache
      shared_es_api->ClearCache(Client());
    });
  }
}

NSArray<NSNumber*>* AuthResultCache::CacheCounts() {
  return @[ @(root_cache_->count()), @(nonroot_cache_->count()) ];
}

} // namespace santa::santad::event_providers
