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
#include <bsm/libbsm.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#include <memory>

#include "Source/common/TestUtils.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityClient.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

using santa::santad::event_providers::endpoint_security::Client;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::EnrichedClose;
using santa::santad::event_providers::endpoint_security::EnrichedFile;
using santa::santad::event_providers::endpoint_security::EnrichedMessage;
using santa::santad::event_providers::endpoint_security::EnrichedProcess;
using santa::santad::event_providers::endpoint_security::Message;

class MockEndpointSecurityAPI : public EndpointSecurityAPI {
public:
  MOCK_METHOD(es_message_t*, RetainMessage, (const es_message_t* msg));
  MOCK_METHOD(void, ReleaseMessage, (es_message_t* msg));

  MOCK_METHOD(bool, Subscribe, (const Client &client,
                                const std::set<es_event_type_t>&));
  MOCK_METHOD(bool, ClearCache, (const Client &client));

  MOCK_METHOD(bool, MuteProcess, (const Client &client,
                                  const audit_token_t* tok));

  MOCK_METHOD(bool, RespondAuthResult, (const Client &client,
                                        const Message& msg,
                                        es_auth_result_t result,
                                        bool cache));
};

@interface SNTEndpointSecurityClient (Testing)
- (bool)muteSelf;
@end

@interface SNTEndpointSecurityClientTest : XCTestCase
@end

@implementation SNTEndpointSecurityClientTest

- (void)setUp {
}

- (void)testPopulateAuditTokenSelf {
  audit_token_t myAuditToken;

  [SNTEndpointSecurityClient populateAuditTokenSelf:&myAuditToken];

  XCTAssertEqual(audit_token_to_pid(myAuditToken), getpid());
  XCTAssertNotEqual(audit_token_to_pidversion(myAuditToken), 0);
}

- (void)testMuteSelf {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  SNTEndpointSecurityClient *client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:mockESApi];

  EXPECT_CALL(*mockESApi, MuteProcess(testing::_, testing::_))
      .WillOnce(testing::Return(true))
      .WillOnce(testing::Return(false));

  XCTAssertTrue([client muteSelf]);
  XCTAssertFalse([client muteSelf]);

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
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

- (void)testProcessEnrichedMessageHandler {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  // Note: In this test, `RetainMessage` isn't setup to return anything. This
  // means that the underlying `es_msg_` in the `Message` object is NULL, and
  // therefore no call to `ReleaseMessage` is ever made (hence no expectations).
  // Because we don't need to operate on the es_msg_, this simplifies the test.
  EXPECT_CALL(*mockESApi, RetainMessage(testing::_));

  SNTEndpointSecurityClient *client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:mockESApi];

  es_message_t esMsg;
  auto enrichedMsg = std::make_shared<EnrichedMessage>(
      EnrichedClose(
          Message(mockESApi, &esMsg),
          EnrichedProcess(std::nullopt,
                          std::nullopt,
                          std::nullopt,
                          std::nullopt,
                          EnrichedFile(std::nullopt, std::nullopt, std::nullopt)),
          EnrichedFile(std::nullopt, std::nullopt, std::nullopt)));

  [client processEnrichedMessage:enrichedMsg
                         handler:^(std::shared_ptr<EnrichedMessage> msg) {
    dispatch_semaphore_signal(sema);
  }];

  XCTAssertEqual(0,
                 dispatch_semaphore_wait(
                     sema,
                     dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)),
                 "Handler block not called within expected time window");

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testIsDatabasePath {
  XCTAssertTrue([SNTEndpointSecurityClient
      isDatabasePath:"/private/var/db/santa/rules.db"]);
  XCTAssertTrue([SNTEndpointSecurityClient
      isDatabasePath:"/private/var/db/santa/events.db"]);

  XCTAssertFalse([SNTEndpointSecurityClient isDatabasePath:"/not/a/db/path"]);
}

@end
