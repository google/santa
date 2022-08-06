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

#include <EndpointSecurity/EndpointSecurity.h>
#include <Foundation/Foundation.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <memory>

#include "Source/common/SNTCommon.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"

using santa::santad::event_providers::AuthResultCache;
using santa::santad::event_providers::FlushCacheMode;
using santa::santad::event_providers::endpoint_security::Client;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;

// Grab the st_dev number of the root volume to match the root cache
static uint64_t RootDevno() {
  static dispatch_once_t once_token;
  static uint64_t devno;
  dispatch_once(&once_token, ^{
    struct stat sb;
    stat("/", &sb);
    devno = sb.st_dev;
  });
  return devno;
}

static inline es_file_t MakeCacheableFile(uint64_t devno, uint64_t ino) {
  return es_file_t{
    .path = {},
    .path_truncated = false,
    .stat = {
      .st_dev = (dev_t)devno,
      .st_ino = ino
    }
  };
}

static inline santa_vnode_id_t VnodeForFile(const es_file_t* es_file) {
  return santa_vnode_id_t{
    .fsid = (uint64_t)es_file->stat.st_dev,
    .fileid = es_file->stat.st_ino,
  };
}

namespace santa::santad::event_providers {

class AuthResultCacheTest : public AuthResultCache {
public:
  // Make base class constructors visible
  using AuthResultCache::AuthResultCache;
  // AuthResultCacheTest(std::shared_ptr<EndpointSecurityAPI> es_api)
  //   : AuthResultCache(std::move(es_api)) {}

  auto RootCache() { return root_cache_; }
  auto NonRootCache() { return nonroot_cache_; }
};

} // namespace santa::santad::event_providers

using santa::santad::event_providers::AuthResultCacheTest;

static inline void ExpectCacheCounts(std::shared_ptr<AuthResultCache> cache,
                                     uint64_t root_count,
                                     uint64_t nonroot_count) {
  NSArray<NSNumber*> *counts = cache->CacheCounts();

  EXPECT_TRUE(counts != nil && [counts count] == 2);
  EXPECT_TRUE(counts[0] != nil &&
              [counts[0] unsignedLongLongValue] == root_count);
  EXPECT_TRUE(counts[1] != nil &&
              [counts[1] unsignedLongLongValue] == nonroot_count);
}

class MockEndpointSecurityAPI : public EndpointSecurityAPI {
  public:
    MOCK_METHOD(bool, ClearCache, (const Client &client));
};

TEST(AuthResultCache, EmptyCacheExpectedNumberOfCacheCounts) {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  auto cache = std::make_shared<AuthResultCache>(esapi);

  ExpectCacheCounts(cache, 0, 0);
}

TEST(AuthResultCache, BasicOperation) {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  auto cache = std::make_shared<AuthResultCacheTest>(esapi);

  es_file_t root_file = MakeCacheableFile(RootDevno(), 111);
  es_file_t nonroot_file = MakeCacheableFile(RootDevno() + 123, 222);

  // Add the root file to the cache
  cache->AddToCache(&root_file, ACTION_REQUEST_BINARY);

  ExpectCacheCounts(cache, 1, 0);
  EXPECT_EQ(cache->CheckCache(&root_file), ACTION_REQUEST_BINARY);
  EXPECT_EQ(cache->CheckCache(&nonroot_file), ACTION_UNSET);

  // Now add the non-root file
  cache->AddToCache(&nonroot_file, ACTION_REQUEST_BINARY);

  ExpectCacheCounts(cache, 1, 1);
  EXPECT_EQ(cache->CheckCache(&root_file), ACTION_REQUEST_BINARY);
  EXPECT_EQ(cache->CheckCache(&nonroot_file), ACTION_REQUEST_BINARY);

  // Update the cached values
  cache->AddToCache(&root_file, ACTION_RESPOND_ALLOW);
  cache->AddToCache(&nonroot_file, ACTION_RESPOND_DENY);

  ExpectCacheCounts(cache, 1, 1);
  EXPECT_EQ(cache->CheckCache(VnodeForFile(&root_file)), ACTION_RESPOND_ALLOW);
  EXPECT_EQ(cache->CheckCache(VnodeForFile(&nonroot_file)), ACTION_RESPOND_DENY);

  // Remove the root file
  cache->RemoveFromCache(&root_file);

  ExpectCacheCounts(cache, 0, 1);
  EXPECT_EQ(cache->CheckCache(&root_file), ACTION_UNSET);
  EXPECT_EQ(cache->CheckCache(&nonroot_file), ACTION_RESPOND_DENY);
}

TEST(AuthResultCache, FlushCache) {
  auto mock_esapi = std::make_shared<MockEndpointSecurityAPI>();
  auto cache = std::make_shared<AuthResultCache>(mock_esapi);

  es_file_t root_file = MakeCacheableFile(RootDevno(), 111);
  es_file_t nonroot_file = MakeCacheableFile(RootDevno() + 123, 111);

  cache->AddToCache(&root_file, ACTION_REQUEST_BINARY);
  cache->AddToCache(&nonroot_file, ACTION_REQUEST_BINARY);

  ExpectCacheCounts(cache, 1, 1);

  // Flush non-root only
  cache->FlushCache(FlushCacheMode::kNonRootOnly);

  ExpectCacheCounts(cache, 1, 0);

  // Add back the non-root file
  cache->AddToCache(&nonroot_file, ACTION_REQUEST_BINARY);

  ExpectCacheCounts(cache, 1, 1);

  // Flush all caches
  // The call to ClearCache is asynchronous. Use a semaphore to
  // be notified when the mock is called.
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  EXPECT_CALL(*mock_esapi, ClearCache(testing::_))
      .WillOnce(testing::InvokeWithoutArgs(^() {
          dispatch_semaphore_signal(sema);
          return true;
      }));
  cache->FlushCache(FlushCacheMode::kAllCaches);

  ASSERT_EQ(
      0,
      dispatch_semaphore_wait(
          sema,
          dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)))
      << "ClearCache wasn't called within expected window";

  ExpectCacheCounts(cache, 0, 0);
}

// TEST(AddToCache, CacheStateMachine) {
//   auto esapi = std::make_shared<EndpointSecurityAPI>();
//   auto cache = std::make_shared<AuthResultCacheTest>(esapi);
// }

// } // namespace santa::santad::event_providers
