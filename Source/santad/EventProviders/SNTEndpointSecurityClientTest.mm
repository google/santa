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
#include <EndpointSecurity/EndpointSecurity.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#include <memory>

#include "Source/common/TestUtils.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityClient.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

using santa::santad::event_providers::endpoint_security::Client;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Message;

class MockEndpointSecurityAPI : public EndpointSecurityAPI {
public:
  MOCK_METHOD(es_message_t*, RetainMessage, (const es_message_t* msg));
  MOCK_METHOD(void, ReleaseMessage, (es_message_t* msg));

  MOCK_METHOD(bool, Subscribe, (const Client &client,
                                const std::set<es_event_type_t>&));
  MOCK_METHOD(bool, ClearCache, (const Client &client));

  MOCK_METHOD(bool, RespondAuthResult, (const Client &client,
                                        const Message& msg,
                                        es_auth_result_t result,
                                        bool cache));
};

@interface SNTEndpointSecurityClientTest : XCTestCase
@end

@implementation SNTEndpointSecurityClientTest {
}

- (void)setUp {
}

- (void)testClearCache {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  SNTEndpointSecurityClient *client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:mockESApi];

  // Test the underlying clear cache impl returning both true and false
  EXPECT_CALL(*mockESApi, ClearCache(testing::_))
      .WillOnce(testing::Return(true))
      .WillOnce(testing::Return(false));

  XCTAssertTrue([client clearCache]);
  XCTAssertFalse([client clearCache]);

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testSubscribe {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  SNTEndpointSecurityClient *client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:mockESApi];

  std::set<es_event_type_t> events = {
      ES_EVENT_TYPE_NOTIFY_CLOSE,
      ES_EVENT_TYPE_NOTIFY_EXIT,
      };

  // Test the underlying subscribe impl returning both true and false
  EXPECT_CALL(*mockESApi, Subscribe(testing::_, events))
      .WillOnce(testing::Return(true))
      .WillOnce(testing::Return(false));

  XCTAssertTrue([client subscribe:events]);
  XCTAssertFalse([client subscribe:events]);

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testSubscribeAndClearCache {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  SNTEndpointSecurityClient *client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:mockESApi];

  // Have subscribe fail the first time, meaning clear cache only called once.
  EXPECT_CALL(*mockESApi, ClearCache(testing::_))
      .WillOnce(testing::Return(true))
      .After(
          EXPECT_CALL(*mockESApi, Subscribe(testing::_, testing::_))
              .WillOnce(testing::Return(false))
              .WillOnce(testing::Return(true)));

  XCTAssertFalse([client subscribeAndClearCache:{}]);
  XCTAssertTrue([client subscribeAndClearCache:{}]);

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testRespondToMessageWithAuthResultCacheable {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  es_message_t es_msg;

  es_auth_result_t result = ES_AUTH_RESULT_DENY;
  bool cacheable = true;

  // Have subscribe fail the first time, meaning clear cache only called once.
  EXPECT_CALL(*mockESApi, RespondAuthResult(testing::_,
                                            testing::_,
                                            result,
                                            cacheable))
      .WillOnce(testing::Return(true));

  EXPECT_CALL(*mockESApi, ReleaseMessage(testing::_))
      .After(EXPECT_CALL(*mockESApi, RetainMessage(testing::_))
          .WillOnce(testing::Return(&es_msg)));

  SNTEndpointSecurityClient *client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:mockESApi];

  {
    Message msg(mockESApi, &es_msg);
    XCTAssertTrue([client respondToMessage:msg
                            withAuthResult:result
                                 cacheable:cacheable]);
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

@end
