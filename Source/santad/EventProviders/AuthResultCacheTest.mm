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
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <time.h>

#include <memory>

#include "Source/common/SNTCommon.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"

using santa::santad::event_providers::AuthResultCache;
using santa::santad::event_providers::FlushCacheMode;
using santa::santad::event_providers::endpoint_security::Client;

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
    .path = {}, .path_truncated = false, .stat = {.st_dev = (dev_t)devno, .st_ino = ino}};
}

static inline santa_vnode_id_t VnodeForFile(const es_file_t *es_file) {
  return santa_vnode_id_t{
    .fsid = (uint64_t)es_file->stat.st_dev,
    .fileid = es_file->stat.st_ino,
  };
}

static inline void AssertCacheCounts(std::shared_ptr<AuthResultCache> cache, uint64_t root_count,
                                     uint64_t nonroot_count) {
  NSArray<NSNumber *> *counts = cache->CacheCounts();

  XCTAssertNotNil(counts);
  XCTAssertEqual([counts count], 2);
  XCTAssertNotNil(counts[0]);
  XCTAssertNotNil(counts[1]);
  XCTAssertEqual([counts[0] unsignedLongLongValue], root_count);
  XCTAssertEqual([counts[1] unsignedLongLongValue], nonroot_count);
}

@interface AuthResultCacheTest : XCTestCase
@end

@implementation AuthResultCacheTest

- (void)testEmptyCacheExpectedNumberOfCacheCounts {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  auto cache = std::make_shared<AuthResultCache>(esapi);

  AssertCacheCounts(cache, 0, 0);
}

- (void)testBasicOperation {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  auto cache = std::make_shared<AuthResultCache>(esapi);

  es_file_t root_file = MakeCacheableFile(RootDevno(), 111);
  es_file_t nonroot_file = MakeCacheableFile(RootDevno() + 123, 222);

  // Add the root file to the cache
  cache->AddToCache(&root_file, ACTION_REQUEST_BINARY);

  AssertCacheCounts(cache, 1, 0);
  XCTAssertEqual(cache->CheckCache(&root_file), ACTION_REQUEST_BINARY);
  XCTAssertEqual(cache->CheckCache(&nonroot_file), ACTION_UNSET);

  // Now add the non-root file
  cache->AddToCache(&nonroot_file, ACTION_REQUEST_BINARY);

  AssertCacheCounts(cache, 1, 1);
  XCTAssertEqual(cache->CheckCache(&root_file), ACTION_REQUEST_BINARY);
  XCTAssertEqual(cache->CheckCache(&nonroot_file), ACTION_REQUEST_BINARY);

  // Update the cached values
  cache->AddToCache(&root_file, ACTION_RESPOND_ALLOW);
  cache->AddToCache(&nonroot_file, ACTION_RESPOND_DENY);

  AssertCacheCounts(cache, 1, 1);
  XCTAssertEqual(cache->CheckCache(VnodeForFile(&root_file)), ACTION_RESPOND_ALLOW);
  XCTAssertEqual(cache->CheckCache(VnodeForFile(&nonroot_file)), ACTION_RESPOND_DENY);

  // Remove the root file
  cache->RemoveFromCache(&root_file);

  AssertCacheCounts(cache, 0, 1);
  XCTAssertEqual(cache->CheckCache(&root_file), ACTION_UNSET);
  XCTAssertEqual(cache->CheckCache(&nonroot_file), ACTION_RESPOND_DENY);
}

- (void)testFlushCache {
  auto mock_esapi = std::make_shared<MockEndpointSecurityAPI>();
  auto cache = std::make_shared<AuthResultCache>(mock_esapi);

  es_file_t root_file = MakeCacheableFile(RootDevno(), 111);
  es_file_t nonroot_file = MakeCacheableFile(RootDevno() + 123, 111);

  cache->AddToCache(&root_file, ACTION_REQUEST_BINARY);
  cache->AddToCache(&nonroot_file, ACTION_REQUEST_BINARY);

  AssertCacheCounts(cache, 1, 1);

  // Flush non-root only
  cache->FlushCache(FlushCacheMode::kNonRootOnly);

  AssertCacheCounts(cache, 1, 0);

  // Add back the non-root file
  cache->AddToCache(&nonroot_file, ACTION_REQUEST_BINARY);

  AssertCacheCounts(cache, 1, 1);

  // Flush all caches
  // The call to ClearCache is asynchronous. Use a semaphore to
  // be notified when the mock is called.
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  EXPECT_CALL(*mock_esapi, ClearCache).WillOnce(testing::InvokeWithoutArgs(^() {
    dispatch_semaphore_signal(sema);
    return true;
  }));
  cache->FlushCache(FlushCacheMode::kAllCaches);

  XCTAssertEqual(0,
                 dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)),
                 "ClearCache wasn't called within expected time window");

  XCTBubbleMockVerifyAndClearExpectations(mock_esapi.get());

  AssertCacheCounts(cache, 0, 0);
}

- (void)testCacheStateMachine {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  auto cache = std::make_shared<AuthResultCache>(esapi);

  es_file_t root_file = MakeCacheableFile(RootDevno(), 111);

  // Cached items must first be in the ACTION_REQUEST_BINARY state
  XCTAssertFalse(cache->AddToCache(&root_file, ACTION_RESPOND_ALLOW));
  XCTAssertFalse(cache->AddToCache(&root_file, ACTION_RESPOND_ALLOW_COMPILER));
  XCTAssertFalse(cache->AddToCache(&root_file, ACTION_RESPOND_DENY));
  XCTAssertEqual(cache->CheckCache(&root_file), ACTION_UNSET);

  XCTAssertTrue(cache->AddToCache(&root_file, ACTION_REQUEST_BINARY));
  XCTAssertEqual(cache->CheckCache(&root_file), ACTION_REQUEST_BINARY);

  // Items in the `ACTION_REQUEST_BINARY` state cannot reenter the same state
  XCTAssertFalse(cache->AddToCache(&root_file, ACTION_REQUEST_BINARY));
  XCTAssertEqual(cache->CheckCache(&root_file), ACTION_REQUEST_BINARY);

  santa_action_t allowed_transitions[] = {
    ACTION_RESPOND_ALLOW,
    ACTION_RESPOND_ALLOW_COMPILER,
    ACTION_RESPOND_DENY,
  };

  for (size_t i = 0; i < sizeof(allowed_transitions) / sizeof(allowed_transitions[0]); i++) {
    // First make sure the item doesn't exist
    cache->RemoveFromCache(&root_file);
    XCTAssertEqual(cache->CheckCache(&root_file), ACTION_UNSET);

    // Now add the item to be in the first allowed state
    XCTAssertTrue(cache->AddToCache(&root_file, ACTION_REQUEST_BINARY));
    XCTAssertEqual(cache->CheckCache(&root_file), ACTION_REQUEST_BINARY);

    // Now assert the allowed transition
    XCTAssertTrue(cache->AddToCache(&root_file, allowed_transitions[i]));
    XCTAssertEqual(cache->CheckCache(&root_file), allowed_transitions[i]);
  }
}

- (void)testCacheExpiry {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  // Create a cache with a lowered cache expiry value
  uint64_t expiry_ms = 250;
  auto cache = std::make_shared<AuthResultCache>(esapi, expiry_ms);

  es_file_t root_file = MakeCacheableFile(RootDevno(), 111);

  // Add a file to the cache and put into the ACTION_RESPOND_DENY state
  XCTAssertTrue(cache->AddToCache(&root_file, ACTION_REQUEST_BINARY));
  XCTAssertTrue(cache->AddToCache(&root_file, ACTION_RESPOND_DENY));

  // Ensure the file exists
  XCTAssertEqual(cache->CheckCache(&root_file), ACTION_RESPOND_DENY);

  // Wait for the item to expire
  SleepMS(expiry_ms);

  // Check cache counts to make sure the item still exists
  AssertCacheCounts(cache, 1, 0);

  // Now check the cache, which will remove the item
  XCTAssertEqual(cache->CheckCache(&root_file), ACTION_UNSET);
  AssertCacheCounts(cache, 0, 0);
}

@end
