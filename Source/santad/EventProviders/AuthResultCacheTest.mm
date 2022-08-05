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

#include <Foundation/Foundation.h>
#include <gtest/gtest.h>

#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"

using santa::santad::event_providers::AuthResultCache;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;

TEST(CacheCountsTest, ReturnsExpectedNumberOfCacheCounts) {
  auto esapi = std::make_shared<EndpointSecurityAPI>();
  auto cache = std::make_shared<AuthResultCache>(esapi);

  NSArray<NSNumber*> *counts = cache->CacheCounts();

  EXPECT_TRUE(counts != nil && [counts count] == 2);
  EXPECT_TRUE(counts[0] != nil && [counts[0] unsignedLongLongValue] == 0);
  EXPECT_TRUE(counts[1] != nil && [counts[1] unsignedLongLongValue] == 0);
}
