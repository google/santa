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

#ifndef SANTA__SANTAD__EVENTPROVIDERS_AUTHRESULTCACHE_H
#define SANTA__SANTAD__EVENTPROVIDERS_AUTHRESULTCACHE_H

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <sys/stat.h>
#include <memory>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTMetricSet.h"
#include "Source/common/SantaCache.h"
#import "Source/common/SantaVnode.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"

namespace santa::santad::event_providers {

enum class FlushCacheMode {
  kNonRootOnly,
  kAllCaches,
};

enum class FlushCacheReason {
  kClientModeChanged,
  kPathRegexChanged,
  kRulesChanged,
  kStaticRulesChanged,
  kExplicitCommand,
  kFilesystemUnmounted,
  kEntitlementsPrefixFilterChanged,
  kEntitlementsTeamIDFilterChanged,
};

class AuthResultCache {
 public:
  // Santa currently only flushes caches when new DENY rules are added, not
  // ALLOW rules. This means cache_deny_time_ms should be low enough so that if a
  // previously denied binary is allowed, it can be re-executed by the user in a
  // timely manner. But the value should be high enough to allow the cache to be
  // effective in the event the binary is executed in rapid succession.
  static std::unique_ptr<AuthResultCache> Create(
    std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> esapi,
    SNTMetricSet *metric_set, uint64_t cache_deny_time_ms = 1500);

  AuthResultCache(
    std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> esapi,
    SNTMetricCounter *flush_count, uint64_t cache_deny_time_ms = 1500);
  virtual ~AuthResultCache();

  AuthResultCache(AuthResultCache &&other) = delete;
  AuthResultCache &operator=(AuthResultCache &&rhs) = delete;
  AuthResultCache(const AuthResultCache &other) = delete;
  AuthResultCache &operator=(const AuthResultCache &other) = delete;

  virtual bool AddToCache(const es_file_t *es_file, SNTAction decision);
  virtual void RemoveFromCache(const es_file_t *es_file);
  virtual SNTAction CheckCache(const es_file_t *es_file);
  virtual SNTAction CheckCache(SantaVnode vnode_id);

  virtual void FlushCache(FlushCacheMode mode, FlushCacheReason reason);

  virtual NSArray<NSNumber *> *CacheCounts();

 private:
  virtual SantaCache<SantaVnode, uint64_t> *CacheForVnodeID(SantaVnode vnode_id);

  SantaCache<SantaVnode, uint64_t> *root_cache_;
  SantaCache<SantaVnode, uint64_t> *nonroot_cache_;

  std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> esapi_;
  SNTMetricCounter *flush_count_;
  uint64_t root_devno_;
  uint64_t cache_deny_time_ns_;
  dispatch_queue_t q_;
};

}  // namespace santa::santad::event_providers

#endif
