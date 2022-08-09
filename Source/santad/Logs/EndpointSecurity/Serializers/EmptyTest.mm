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

#import <Foundation/Foundation.h>
#include <gtest/gtest.h>

#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Empty.h"

using santa::santad::logs::endpoint_security::serializers::Empty;

namespace es = santa::santad::event_providers::endpoint_security;

TEST(Empty, AllSerializersReturnEmptyVector) {
  auto empty = Empty::Create();

  // We can get away with passing a fake argument to the `Serialize*` methods
  // instead of constructing real ones since the Empty class never touches the
  // input parameter.
  int fake;
  EXPECT_EQ(empty->SerializeMessage(*(es::EnrichedClose*)&fake).size(), 0);
  EXPECT_EQ(empty->SerializeMessage(*(es::EnrichedExchange*)&fake).size(), 0);
  EXPECT_EQ(empty->SerializeMessage(*(es::EnrichedExec*)&fake).size(), 0);
  EXPECT_EQ(empty->SerializeMessage(*(es::EnrichedExit*)&fake).size(), 0);
  EXPECT_EQ(empty->SerializeMessage(*(es::EnrichedFork*)&fake).size(), 0);
  EXPECT_EQ(empty->SerializeMessage(*(es::EnrichedLink*)&fake).size(), 0);
  EXPECT_EQ(empty->SerializeMessage(*(es::EnrichedRename*)&fake).size(), 0);
  EXPECT_EQ(empty->SerializeMessage(*(es::EnrichedUnlink*)&fake).size(), 0);

  EXPECT_EQ(empty->SerializeAllowlist(*(es::Message*)&fake, "").size(), 0);
  EXPECT_EQ(empty->SerializeBundleHashingEvent(nil).size(), 0);
  EXPECT_EQ(empty->SerializeDiskAppeared(nil).size(), 0);
  EXPECT_EQ(empty->SerializeDiskDisappeared(nil).size(), 0);
}
