/// Copyright 2021 Google Inc. All rights reserved.
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

#include <EndpointSecurity/ESTypes.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#import <OCMock/OCMock.h>
#include <memory>
#import <XCTest/XCTest.h>

#include "Source/common/TestUtils.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"

@interface SNTEndpointSecurityAuthorizerTest : XCTestCase
@end

@implementation SNTEndpointSecurityAuthorizerTest

- (void)testEnable {
  // Ensure the client subscribes to expected event types
  std::set<es_event_type_t> expectedEventSubs{ ES_EVENT_TYPE_AUTH_EXEC };
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  id authClient =
      [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi];

  EXPECT_CALL(*mockESApi, ClearCache(testing::_))
    .After(
        EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
            .WillOnce(testing::Return(true)))
    .WillOnce(testing::Return(true));

  [authClient enable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

@end
