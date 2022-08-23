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
#include "Source/santad/SNTExecutionController.h"
#import <XCTest/XCTest.h>

#include <memory>
#include <set>

#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"

using santa::santad::event_providers::endpoint_security::Client;
using santa::santad::event_providers::endpoint_security::Message;

@interface SNTEndpointSecurityAuthorizer (Testing)
- (bool)postAction:(santa_action_t)action forMessage:(const Message&)esMsg;
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

- (void)testHandleShouldProcessExecEvent {

}

- (void)testHandleMessage {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file, {}, {});
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, false);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, NewClient(testing::_))
      .WillOnce(testing::Return(Client(nullptr, ES_NEW_CLIENT_RESULT_SUCCESS)));
  EXPECT_CALL(*mockESApi, MuteProcess(testing::_, testing::_))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, ReleaseMessage(testing::_))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*mockESApi, RetainMessage(testing::_))
      .WillRepeatedly(testing::Return(&esMsg));

  SNTEndpointSecurityAuthorizer *authClient =
      [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                    logger:nullptr
                                            execController:self.mockExecController
                                        compilerController:nil
                                           authResultCache:nullptr];

  id mockAuthClient = OCMPartialMock(authClient);

  // Test unhandled event type
  {
    // Temporarily change the event type
    esMsg.event_type = ES_EVENT_TYPE_NOTIFY_EXEC;
    XCTAssertThrows([authClient handleMessage:Message(mockESApi, &esMsg)]);
    esMsg.event_type = ES_EVENT_TYPE_AUTH_EXEC;
  }

  // Test SNTExecutionController determines the event shouldn't be processed
  {
    Message msg(mockESApi, &esMsg);

    OCMExpect([self.mockExecController synchronousShouldProcessExecEvent:msg])
      .ignoringNonObjectArgs()
      .andReturn(NO);

    OCMExpect([mockAuthClient postAction:ACTION_RESPOND_DENY
                              forMessage:Message(mockESApi, &esMsg)])
        .ignoringNonObjectArgs();
    OCMStub([mockAuthClient postAction:ACTION_RESPOND_DENY
                            forMessage:Message(mockESApi, &esMsg)])
        .ignoringNonObjectArgs()
        .andDo(nil);

    [mockAuthClient handleMessage:std::move(msg)];
    XCTAssertTrue(OCMVerifyAll(mockAuthClient));
  }

  // Test SNTExecutionController determines the event should be processed and
  // processMessage:handler: is called.
  {
    Message msg(mockESApi, &esMsg);

    OCMExpect([self.mockExecController synchronousShouldProcessExecEvent:msg])
      .ignoringNonObjectArgs()
      .andReturn(YES);

    OCMExpect([mockAuthClient processMessage:Message(mockESApi, &esMsg)
                                     handler:[OCMArg any]])
        .ignoringNonObjectArgs();
    OCMStub([mockAuthClient processMessage:Message(mockESApi, &esMsg)
                                     handler:[OCMArg any]])
        .ignoringNonObjectArgs()
        .andDo(nil);

    [mockAuthClient handleMessage:std::move(msg)];
    XCTAssertTrue(OCMVerifyAll(mockAuthClient));
  }

  [mockAuthClient stopMocking];
}

@end
