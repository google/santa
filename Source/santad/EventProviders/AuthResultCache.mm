
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
#import "Source/common/SantaVnodeHash.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"

using santa::santad::event_providers::endpoint_security::Client;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;

static NSString *const kFlushCacheReasonClientModeChanged = @"ClientModeChanged";
static NSString *const kFlushCacheReasonPathRegexChanged = @"PathRegexChanged";
static NSString *const kFlushCacheReasonRulesChanged = @"RulesChanged";
static NSString *const kFlushCacheReasonStaticRulesChanged = @"StaticRulesChanged";
static NSString *const kFlushCacheReasonExplicitCommand = @"ExplicitCommand";
static NSString *const kFlushCacheReasonFilesystemUnmounted = @"FilesystemUnmounted";
static NSString *const kFlushCacheReasonEntitlementsPrefixFilterChanged =
  @"EntitlementsPrefixFilterChanged";
static NSString *const kFlushCacheReasonEntitlementsTeamIDFilterChanged =
  @"EntitlementsTeamIDFilterChanged";

namespace santa::santad::event_providers {

static inline uint64_t GetCurrentUptime() {
  return clock_gettime_nsec_np(CLOCK_MONOTONIC);
}

// Decision is stored in upper 8 bits, timestamp in remaining 56.
static inline uint64_t CacheableAction(SNTAction action, uint64_t timestamp = GetCurrentUptime()) {
  return ((uint64_t)action << 56) | (timestamp & 0xFFFFFFFFFFFFFF);
}

static inline SNTAction ActionFromCachedValue(uint64_t cachedValue) {
  return (SNTAction)(cachedValue >> 56);
}

static inline uint64_t TimestampFromCachedValue(uint64_t cachedValue) {
  return (cachedValue & ~(0xFF00000000000000));
}

NSString *const FlushCacheReasonToString(FlushCacheReason reason) {
  switch (reason) {
    case FlushCacheReason::kClientModeChanged: return kFlushCacheReasonClientModeChanged;
    case FlushCacheReason::kPathRegexChanged: return kFlushCacheReasonPathRegexChanged;
    case FlushCacheReason::kRulesChanged: return kFlushCacheReasonRulesChanged;
    case FlushCacheReason::kStaticRulesChanged: return kFlushCacheReasonStaticRulesChanged;
    case FlushCacheReason::kExplicitCommand: return kFlushCacheReasonExplicitCommand;
    case FlushCacheReason::kFilesystemUnmounted: return kFlushCacheReasonFilesystemUnmounted;
    case FlushCacheReason::kEntitlementsPrefixFilterChanged:
      return kFlushCacheReasonEntitlementsPrefixFilterChanged;
    case FlushCacheReason::kEntitlementsTeamIDFilterChanged:
      return kFlushCacheReasonEntitlementsTeamIDFilterChanged;
    default:
      [NSException raise:@"Invalid reason"
                  format:@"Unknown reason value: %d", static_cast<int>(reason)];
      return nil;
  }
}

std::unique_ptr<AuthResultCache> AuthResultCache::Create(std::shared_ptr<EndpointSecurityAPI> esapi,
                                                         SNTMetricSet *metric_set,
                                                         uint64_t cache_deny_time_ms) {
  SNTMetricCounter *flush_count =
    [metric_set counterWithName:@"/santa/flush_count"
                     fieldNames:@[ @"Reason" ]
                       helpText:@"Count of times the auth result cache is flushed by reason"];

  return std::make_unique<AuthResultCache>(esapi, flush_count, cache_deny_time_ms);
}

AuthResultCache::AuthResultCache(std::shared_ptr<EndpointSecurityAPI> esapi,
                                 SNTMetricCounter *flush_count, uint64_t cache_deny_time_ms)
    : esapi_(esapi),
      flush_count_(flush_count),
      cache_deny_time_ns_(cache_deny_time_ms * NSEC_PER_MSEC) {
  root_cache_ = new SantaCache<SantaVnode, uint64_t>();
  nonroot_cache_ = new SantaCache<SantaVnode, uint64_t>();

  struct stat sb;
  if (stat("/", &sb) == 0) {
    root_devno_ = sb.st_dev;
  }

  q_ = dispatch_queue_create(
    "com.google.santa.daemon.auth_result_cache.q",
    dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,
                                            QOS_CLASS_USER_INTERACTIVE, 0));
}

AuthResultCache::~AuthResultCache() {
  delete root_cache_;
  delete nonroot_cache_;
}

bool AuthResultCache::AddToCache(const es_file_t *es_file, SNTAction decision) {
  SantaVnode vnode_id = SantaVnode::VnodeForFile(es_file);
  SantaCache<SantaVnode, uint64_t> *cache = CacheForVnodeID(vnode_id);
  switch (decision) {
    case SNTActionRequestBinary:
      return cache->set(vnode_id, CacheableAction(SNTActionRequestBinary, 0), 0);
    case SNTActionRespondAllow: OS_FALLTHROUGH;
    case SNTActionRespondAllowCompiler: OS_FALLTHROUGH;
    case SNTActionRespondDeny:
      return cache->set(vnode_id, CacheableAction(decision),
                        CacheableAction(SNTActionRequestBinary, 0));
    default:
      // This is a programming error. Bail.
      LOGE(@"Invalid cache value, exiting.");
      exit(EXIT_FAILURE);
  }
}

void AuthResultCache::RemoveFromCache(const es_file_t *es_file) {
  SantaVnode vnode_id = SantaVnode::VnodeForFile(es_file);
  CacheForVnodeID(vnode_id)->remove(vnode_id);
}

SNTAction AuthResultCache::CheckCache(const es_file_t *es_file) {
  return CheckCache(SantaVnode::VnodeForFile(es_file));
}

SNTAction AuthResultCache::CheckCache(SantaVnode vnode_id) {
  SantaCache<SantaVnode, uint64_t> *cache = CacheForVnodeID(vnode_id);

  uint64_t cached_val = cache->get(vnode_id);
  if (cached_val == 0) {
    return SNTActionUnset;
  }

  SNTAction result = ActionFromCachedValue(cached_val);

  if (result == SNTActionRespondDeny) {
    uint64_t expiry_time = TimestampFromCachedValue(cached_val) + cache_deny_time_ns_;
    if (expiry_time < GetCurrentUptime()) {
      cache->remove(vnode_id);
      return SNTActionUnset;
    }
  }

  return result;
}

SantaCache<SantaVnode, uint64_t> *AuthResultCache::CacheForVnodeID(SantaVnode vnode_id) {
  return (vnode_id.fsid == root_devno_ || root_devno_ == 0) ? root_cache_ : nonroot_cache_;
}

void AuthResultCache::FlushCache(FlushCacheMode mode, FlushCacheReason reason) {
  nonroot_cache_->clear();
  if (mode == FlushCacheMode::kAllCaches) {
    root_cache_->clear();

    // Clear the ES cache when all local caches are flushed. Assume the ES cache
    // doesn't need to be cleared when only flushing the non-root cache.
    //
    // Calling into ES should be done asynchronously since it could otherwise
    // potentially deadlock.
    auto shared_esapi = esapi_->shared_from_this();
    dispatch_async(q_, ^{
      // ES does not need a connected client to clear cache
      shared_esapi->ClearCache(Client());
    });
  }

  [flush_count_ incrementForFieldValues:@[ FlushCacheReasonToString(reason) ]];
}

NSArray<NSNumber *> *AuthResultCache::CacheCounts() {
  return @[ @(root_cache_->count()), @(nonroot_cache_->count()) ];
}

}  // namespace santa::santad::event_providers
