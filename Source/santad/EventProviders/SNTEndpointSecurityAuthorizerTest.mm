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

#include <EndpointSecurity/ESTypes.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <set>

#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"
#include "Source/santad/Metrics.h"
#import "Source/santad/SNTCompilerController.h"
#import "Source/santad/SNTExecutionController.h"

using santa::santad::EventDisposition;
using santa::santad::event_providers::AuthResultCache;
using santa::santad::event_providers::endpoint_security::Message;

class MockAuthResultCache : public AuthResultCache {
 public:
  using AuthResultCache::AuthResultCache;

  MOCK_METHOD(bool, AddToCache, (const es_file_t *es_file, santa_action_t decision));
  MOCK_METHOD(santa_action_t, CheckCache, (const es_file_t *es_file));
};

@interface SNTEndpointSecurityAuthorizer (Testing)
- (void)processMessage:(const Message &)msg;
- (bool)postAction:(santa_action_t)action forMessage:(const Message &)esMsg;
@end

@interface SNTEndpointSecurityAuthorizerTest : XCTestCase
@property id mockExecController;
@end

@implementation SNTEndpointSecurityAuthorizerTest

- (void)setUp {
  self.mockExecController = OCMStrictClassMock([SNTExecutionController class]);
}

- (void)tearDown {
  [self.mockExecController stopMocking];
}

- (void)testEnable {
  // Ensure the client subscribes to expected event types
  std::set<es_event_type_t> expectedEventSubs{ES_EVENT_TYPE_AUTH_EXEC};
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  id authClient =
    [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                 metrics:nullptr
                                               processor:santa::santad::Processor::kAuthorizer];

  EXPECT_CALL(*mockESApi, ClearCache)
    .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
             .WillOnce(testing::Return(true)))
    .WillOnce(testing::Return(true));

  [authClient enable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testHandleMessage {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage(&esMsg);

  // There is a benign leak of the mock object in this test.
  // `handleMessage:recordEventMetrics:` will call `processMessage:handler:` in the parent
  // class. This will dispatch to two blocks and create message copies. The block that
  // handles `deadline` timeouts will not complete before the test finishes, and the
  // mock object will think that it has been leaked.
  ::testing::Mock::AllowLeak(mockESApi.get());

  dispatch_semaphore_t semaMetrics = dispatch_semaphore_create(0);

  SNTEndpointSecurityAuthorizer *authClient =
    [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                 metrics:nullptr
                                          execController:self.mockExecController
                                      compilerController:nil
                                         authResultCache:nullptr];

  id mockAuthClient = OCMPartialMock(authClient);

  // Test unhandled event type
  {
    // Temporarily change the event type
    esMsg.event_type = ES_EVENT_TYPE_NOTIFY_EXEC;
    XCTAssertThrows([authClient handleMessage:Message(mockESApi, &esMsg)
                           recordEventMetrics:^(EventDisposition d) {
                             XCTFail("Unhandled event types shouldn't call metrics recorder");
                           }]);
    esMsg.event_type = ES_EVENT_TYPE_AUTH_EXEC;
  }

  // Test SNTExecutionController determines the event shouldn't be processed
  {
    Message msg(mockESApi, &esMsg);

    OCMExpect([self.mockExecController synchronousShouldProcessExecEvent:msg])
      .ignoringNonObjectArgs()
      .andReturn(NO);

    OCMExpect([mockAuthClient postAction:ACTION_RESPOND_DENY forMessage:Message(mockESApi, &esMsg)])
      .ignoringNonObjectArgs();
    OCMStub([mockAuthClient postAction:ACTION_RESPOND_DENY forMessage:Message(mockESApi, &esMsg)])
      .ignoringNonObjectArgs()
      .andDo(nil);

    [mockAuthClient handleMessage:std::move(msg)
               recordEventMetrics:^(EventDisposition d) {
                 XCTAssertEqual(d, EventDisposition::kDropped);
                 dispatch_semaphore_signal(semaMetrics);
               }];

    XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
    XCTAssertTrue(OCMVerifyAll(mockAuthClient));
  }

  // Test SNTExecutionController determines the event should be processed and
  // processMessage:handler: is called.
  {
    Message msg(mockESApi, &esMsg);

    OCMExpect([self.mockExecController synchronousShouldProcessExecEvent:msg])
      .ignoringNonObjectArgs()
      .andReturn(YES);

    OCMExpect([mockAuthClient processMessage:Message(mockESApi, &esMsg)]).ignoringNonObjectArgs();
    OCMStub([mockAuthClient processMessage:Message(mockESApi, &esMsg)])
      .ignoringNonObjectArgs()
      .andDo(nil);

    [mockAuthClient handleMessage:std::move(msg)
               recordEventMetrics:^(EventDisposition d) {
                 XCTAssertEqual(d, EventDisposition::kProcessed);
                 dispatch_semaphore_signal(semaMetrics);
               }];

    XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
    XCTAssertTrue(OCMVerifyAll(mockAuthClient));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());

  [mockAuthClient stopMocking];
}

- (void)testProcessMessageWaitThenAllow {
  // This test ensures that if there is an outstanding action for
  // an item, it will check the cache again until a result exists.
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t execFile = MakeESFile("bar");
  es_process_t execProc = MakeESProcess(&execFile, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth);
  esMsg.event.exec.target = &execProc;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage(&esMsg);

  auto mockAuthCache = std::make_shared<MockAuthResultCache>(nullptr);
  EXPECT_CALL(*mockAuthCache, CheckCache)
    .WillOnce(testing::Return(ACTION_REQUEST_BINARY))
    .WillOnce(testing::Return(ACTION_REQUEST_BINARY))
    .WillOnce(testing::Return(ACTION_RESPOND_ALLOW_COMPILER))
    .WillOnce(testing::Return(ACTION_UNSET));
  EXPECT_CALL(*mockAuthCache, AddToCache(testing::_, ACTION_REQUEST_BINARY))
    .WillOnce(testing::Return(true));

  id mockCompilerController = OCMStrictClassMock([SNTCompilerController class]);
  OCMExpect([mockCompilerController setProcess:execProc.audit_token isCompiler:true]);

  SNTEndpointSecurityAuthorizer *authClient =
    [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                 metrics:nullptr
                                          execController:self.mockExecController
                                      compilerController:mockCompilerController
                                         authResultCache:mockAuthCache];
  id mockAuthClient = OCMPartialMock(authClient);

  // This block tests that processing is held up until an outstanding thread
  // processing another event completes and returns a result. This test
  // specifically will check the `ACTION_RESPOND_ALLOW_COMPILER` flow.
  {
    Message msg(mockESApi, &esMsg);
    OCMExpect([mockAuthClient respondToMessage:msg
                                withAuthResult:ES_AUTH_RESULT_ALLOW
                                     cacheable:true]);

    [mockAuthClient processMessage:msg];

    XCTAssertTrue(OCMVerifyAll(mockAuthClient));
    XCTAssertTrue(OCMVerifyAll(mockCompilerController));
  }

  // This block tests uncached events storing appropriate cache marker and then
  // running the exec controller to validate the exec event.
  {
    Message msg(mockESApi, &esMsg);
    OCMExpect([self.mockExecController validateExecEvent:msg postAction:OCMOCK_ANY])
      .ignoringNonObjectArgs();

    [mockAuthClient processMessage:msg];

    XCTAssertTrue(OCMVerifyAll(mockAuthClient));
    XCTAssertTrue(OCMVerifyAll(mockCompilerController));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockAuthCache.get());

  [mockCompilerController stopMocking];
  [mockAuthClient stopMocking];
}

- (void)testPostAction {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t execFile = MakeESFile("bar");
  es_process_t execProc = MakeESProcess(&execFile, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth);
  esMsg.event.exec.target = &execProc;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage(&esMsg);

  auto mockAuthCache = std::make_shared<MockAuthResultCache>(nullptr);
  EXPECT_CALL(*mockAuthCache, AddToCache(&execFile, ACTION_RESPOND_ALLOW_COMPILER))
    .WillOnce(testing::Return(true));
  EXPECT_CALL(*mockAuthCache, AddToCache(&execFile, ACTION_RESPOND_ALLOW))
    .WillOnce(testing::Return(true));
  EXPECT_CALL(*mockAuthCache, AddToCache(&execFile, ACTION_RESPOND_DENY))
    .WillOnce(testing::Return(true));

  id mockCompilerController = OCMStrictClassMock([SNTCompilerController class]);
  OCMExpect([mockCompilerController setProcess:execProc.audit_token isCompiler:true]);

  SNTEndpointSecurityAuthorizer *authClient =
    [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                 metrics:nullptr
                                          execController:self.mockExecController
                                      compilerController:mockCompilerController
                                         authResultCache:mockAuthCache];
  id mockAuthClient = OCMPartialMock(authClient);

  {
    Message msg(mockESApi, &esMsg);

    XCTAssertThrows([mockAuthClient postAction:(santa_action_t)123 forMessage:msg]);

    std::map<santa_action_t, es_auth_result_t> actions = {
      {ACTION_RESPOND_ALLOW_COMPILER, ES_AUTH_RESULT_ALLOW},
      {ACTION_RESPOND_ALLOW, ES_AUTH_RESULT_ALLOW},
      {ACTION_RESPOND_DENY, ES_AUTH_RESULT_DENY},
    };

    for (const auto &kv : actions) {
      OCMExpect([mockAuthClient respondToMessage:msg
                                  withAuthResult:kv.second
                                       cacheable:kv.second == ES_AUTH_RESULT_ALLOW]);

      [mockAuthClient postAction:kv.first forMessage:msg];
    }
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockAuthCache.get());

  [mockCompilerController stopMocking];
  [mockAuthClient stopMocking];
}

@end
