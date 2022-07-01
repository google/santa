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

#include <sys/stat.h>
#import <Foundation/Foundation.h>

#include "Source/common/SantaCache.h"
#import "Source/common/SNTCommon.h"

namespace santa::santad::event_providers {

enum class FlushCacheMode {
  kNonRootOnly,
  kAllCaches,
};

class AuthResultCache {
public:
  AuthResultCache();
  virtual ~AuthResultCache();

  AuthResultCache(AuthResultCache &&other) = delete;
  AuthResultCache& operator=(AuthResultCache &&rhs) = delete;
  AuthResultCache(const AuthResultCache &other) = delete;
  AuthResultCache& operator=(const AuthResultCache &other) = delete;

  virtual void AddToCache(santa_vnode_id_t vnode_id, santa_action_t decision);
  virtual void RemoveFromCache(santa_vnode_id_t vnode_id);
  virtual santa_action_t CheckCache(santa_vnode_id_t vnode_id);

  virtual void FlushCache(FlushCacheMode mode);

  virtual NSArray<NSNumber*>* CacheCounts();

private:
  virtual SantaCache<santa_vnode_id_t, uint64_t>* CacheForVnodeID(
      santa_vnode_id_t vnode_id);

  SantaCache<santa_vnode_id_t, uint64_t> *root_cache_;
  SantaCache<santa_vnode_id_t, uint64_t> *nonroot_cache_;

  uint64_t root_inode_;
};

} // namespace santa::santad::event_providers

#endif
