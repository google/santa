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
#include <mach/mach_time.h>
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

// TODO(mlw): Move mock class to own file to not rewrite everywhere.
class MockEndpointSecurityAPI : public EndpointSecurityAPI {
public:
  MOCK_METHOD(Client, NewClient, (void(^message_handler)
                                  (es_client_t*, Message)));

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
- (NSString*)errorMessageForNewClientResult:(es_new_client_result_t)result;

@property int64_t deadlineMarginMS;
@end

@interface SNTEndpointSecurityClientTest : XCTestCase
@end

@implementation SNTEndpointSecurityClientTest

- (void)testEstablishClientOrDie {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  EXPECT_CALL(*mockESApi, MuteProcess(testing::_, testing::_))
      .WillRepeatedly(testing::Return(true));

  EXPECT_CALL(*mockESApi, NewClient(testing::_))
      .WillOnce(testing::Return(Client()))
      .WillOnce(testing::Return(Client(nullptr,
                                       ES_NEW_CLIENT_RESULT_SUCCESS)));

  SNTEndpointSecurityClient *client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:mockESApi];

  XCTAssertThrows([client
      establishClientOrDie:^(es_client_t *c, Message &&esMsg) {}]);
  XCTAssertNoThrow([client
      establishClientOrDie:^(es_client_t *c, Message &&esMsg) {}]);

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testErrorMessageForNewClientResult {

  std::map<es_new_client_result_t, std::string> resultMessagePairs {
    { ES_NEW_CLIENT_RESULT_SUCCESS, "" },
    { ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED, "Full-disk access not granted" },
    { ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED, "Not entitled" },
    { ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED, "Not running as root" },
    { ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT, "Invalid argument" },
    { ES_NEW_CLIENT_RESULT_ERR_INTERNAL, "Internal error" },
    { ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS, "Too many simultaneous clients" },
    { (es_new_client_result_t)123, "Unknown error" },
  };

  SNTEndpointSecurityClient *client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:nullptr];

  for (auto kv : resultMessagePairs) {
    NSString *message = [client errorMessageForNewClientResult:kv.first];
    XCTAssertEqual(0, strcmp([(message ?: @"") UTF8String], kv.second.c_str()));
  }
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
      .After(
          EXPECT_CALL(*mockESApi, Subscribe(testing::_, testing::_))
              .WillOnce(testing::Return(false))
              .WillOnce(testing::Return(true)))//;
      .WillOnce(testing::Return(true));

  XCTAssertFalse([client subscribeAndClearCache:{}]);
  XCTAssertTrue([client subscribeAndClearCache:{}]);

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testRespondToMessageWithAuthResultCacheable {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  es_message_t esMsg;

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
          .WillOnce(testing::Return(&esMsg)));

  SNTEndpointSecurityClient *client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:mockESApi];

  {
    Message msg(mockESApi, &esMsg);
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

- (void)testProcessMessageHandlerBadEventType {
  es_file_t proc_file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&proc_file, {}, {});
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, ReleaseMessage(testing::_))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*mockESApi, RetainMessage(testing::_))
      .WillRepeatedly(testing::Return(&esMsg));


  SNTEndpointSecurityClient *client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:mockESApi];

  {
    XCTAssertThrows([client processMessage:Message(mockESApi, &esMsg)
                                   handler:^(const Message& msg){}]);
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

// Note: This test triggers a leak warning on the mock object, however it is
// benign. The dispatch block to handle deadline expiration in
// `processMessage:handler:` will retain the mock object an extra time.
// But since this test sets a long deadline in order to ensure the handler block
// runs first, the deadline handler block will not have finished executing by
// the time the test exits, making GMock think the object was leaked.
- (void)testProcessMessageHandler {
  es_file_t proc_file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&proc_file, {}, {});
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_OPEN,
                                     &proc,
                                     false,
                                     45 * 1000); // Long deadline to not hit

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, ReleaseMessage(testing::_))
      .Times(testing::AnyNumber())
      .After(
          EXPECT_CALL(*mockESApi, RetainMessage(testing::_))
              .WillRepeatedly(testing::Return(&esMsg)));

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  SNTEndpointSecurityClient *client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:mockESApi];

  {
    XCTAssertNoThrow([client processMessage:Message(mockESApi, &esMsg)
                                   handler:^(const Message& msg){
      dispatch_semaphore_signal(sema);
    }]);
  }

  XCTAssertEqual(0,
                 dispatch_semaphore_wait(
                     sema,
                     dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)),
                 "Handler block not called within expected time window");

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testProcessMessageHandlerWithDeadlineTimeout {
  // Set a es_message_t deadline of 750ms
  // Set a deadline leeway in the `SNTEndpointSecurityClient` of 500ms
  // Mock `RespondAuthResult` which is called from the deadline handler
  // Signal the semaphore from the mock
  // Wait a few seconds for the semaphore (should take ~250ms)
  //
  // Two semaphotes are used:
  // 1. deadlineSema - used to wait in the handler block until the deadline
  //    block has a chance to execute
  // 2. controlSema - used to block control flow in the test until the
  //    deadlineSema is signaled (or a timeout waiting on deadlineSema)
  es_file_t proc_file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&proc_file, {}, {});
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_OPEN,
                                     &proc,
                                     false,
                                     750); // 750ms timeout

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, ReleaseMessage(testing::_))
      .Times(testing::AnyNumber())
      .After(
          EXPECT_CALL(*mockESApi, RetainMessage(testing::_))
              .WillRepeatedly(testing::Return(&esMsg)));

  dispatch_semaphore_t deadlineSema = dispatch_semaphore_create(0);
  dispatch_semaphore_t controlSema = dispatch_semaphore_create(0);

  EXPECT_CALL(*mockESApi, RespondAuthResult(testing::_,
                                            testing::_,
                                            ES_AUTH_RESULT_DENY,
                                            false))
      .WillOnce(testing::InvokeWithoutArgs(^() {
          // Signal deadlineSema to let the handler block continue execution
          dispatch_semaphore_signal(deadlineSema);
          return true;
      }));

  SNTEndpointSecurityClient *client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:mockESApi];
  client.deadlineMarginMS = 500;

  {
    __block long result;
    XCTAssertNoThrow([client processMessage:Message(mockESApi, &esMsg)
                                    handler:^(const Message& msg){
      result = dispatch_semaphore_wait(
          deadlineSema,
          dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC));

      // Once done waiting on deadlineSema, trigger controlSema to continue test
      dispatch_semaphore_signal(controlSema);
    }]);

    XCTAssertEqual(0,
                    dispatch_semaphore_wait(
                        controlSema,
                        dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC)),
                    "Control sema not signaled within expected time window");

    XCTAssertEqual(result, 0);
  }

  // Allow some time for the threads in `processMessage:handler:` to finish.
  // It isn't critical that they do, but if the dispatch blocks don't complete
  // we may get warnings from GMock about calls to ReleaseMessage after
  // verifying and clearing. Sleep a little bit here to reduce chances of
  // seeing the warning (but still possible)
  SleepMS(100);

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

@end
