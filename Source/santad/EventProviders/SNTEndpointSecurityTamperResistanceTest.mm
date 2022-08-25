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
#import <XCTest/XCTest.h>

#include <map>
#include <memory>
#include <set>

#include "Source/common/TestUtils.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityTamperResistance.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

using santa::santad::event_providers::endpoint_security::Client;
using santa::santad::event_providers::endpoint_security::Message;

// static constexpr std::string_view kEventsDBPath = "/private/var/db/santa/events.db";
// static constexpr std::string_view kRulesDBPath = "/private/var/db/santa/rules.db";
// static constexpr std::string_view kBenignPath = "/some/other/path";
// es_file_t fileEventsDB = MakeESFile(kEventsDBPath.data());
// es_file_t fileRulesDB = MakeESFile(kRulesDBPath.data());
// es_file_t fileBenign = MakeESFile(kBenignPath.data());

// @interface SNTEndpointSecurityTamperResistance(Testing)
// @property std::map<int, int> foo;
// @end

@interface SNTEndpointSecurityTamperResistanceTest : XCTestCase
// @property std::shared_ptr<MockEndpointSecurityAPI> mockESApi;
@end

@implementation SNTEndpointSecurityTamperResistanceTest

- (void)setUp {
  printf("\n\nSET UP\n");
  // self.mockESApi = std::make_shared<MockEndpointSecurityAPI>();
}

- (void)tearDown {
  printf("\n\nTEAR DOWN\n");
}

- (void)testEnable {
  // Ensure the client subscribes to expected event types
  std::set<es_event_type_t> expectedEventSubs{
      ES_EVENT_TYPE_AUTH_KEXTLOAD,
      ES_EVENT_TYPE_AUTH_UNLINK,
      ES_EVENT_TYPE_AUTH_RENAME,
      };

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, NewClient(testing::_))
      .WillOnce(testing::Return(Client(nullptr, ES_NEW_CLIENT_RESULT_SUCCESS)));
  EXPECT_CALL(*mockESApi, MuteProcess(testing::_, testing::_))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, ClearCache(testing::_))
      // .WillOnce(testing::Return(true));
    .After(
        EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
            .WillOnce(testing::Return(true)))
    .WillOnce(testing::Return(true));

  // MockEndpointSecurityAPI mockESApi;

  // EXPECT_CALL(mockESApi, NewClient(testing::_))
  //     .WillOnce(testing::Return(Client(nullptr, ES_NEW_CLIENT_RESULT_SUCCESS)));
  // EXPECT_CALL(mockESApi, MuteProcess(testing::_, testing::_))
  //     .WillOnce(testing::Return(true));
  // EXPECT_CALL(mockESApi, ClearCache(testing::_))
  //     // .WillOnce(testing::Return(true));
  //   .After(
  //       EXPECT_CALL(mockESApi, Subscribe(testing::_, expectedEventSubs))
  //           .WillOnce(testing::Return(true)))
  //   .WillOnce(testing::Return(true));


  SNTEndpointSecurityTamperResistance* tamperClient =
      [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:mockESApi];
  id mockTamperClient = OCMPartialMock(tamperClient);

  // id mockTamperClient = OCMPartialMock(
  //     [[SNTEndpointSecurityTamperResistance alloc]
  //         initWithESAPI:mockESApi]);

  // printf("\n\nCalling `enable`\n");
  [mockTamperClient enable];
  // [tamperClient enable];

  // XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  // XCTBubbleMockVerifyAndClearExpectations(mockESApi);
  // printf("\n\nCalling `stopMocking`\n");
  [mockTamperClient stopMocking];

  // XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  printf("\n\nExiting test\n");
  // mockESApi.reset();
}

// - (void)testHandleMessage {
//   es_file_t file = MakeESFile("foo");
//   es_process_t proc = MakeESProcess(&file, {}, {});
//   es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth);

//   // es_file_t fileEventsDB = MakeESFile("/private/var/db/santa/events.db");
//   // es_file_t fileRulesDB = MakeESFile("/private/var/db/santa/rules.db");
//   // es_file_t fileBenign = MakeESFile("/some/other/path");

//   // std::map<es_file_t*, es_auth_result_t> pathToResult {
//   //   { &fileEventsDB, ES_AUTH_RESULT_DENY },
//   //   { &fileRulesDB, ES_AUTH_RESULT_DENY },
//   //   { &fileBenign, ES_AUTH_RESULT_ALLOW },
//   // };

//   auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
//   EXPECT_CALL(*mockESApi, NewClient(testing::_))
//       .WillOnce(testing::Return(Client(nullptr, ES_NEW_CLIENT_RESULT_SUCCESS)));
//   EXPECT_CALL(*mockESApi, MuteProcess(testing::_, testing::_))
//       .WillOnce(testing::Return(true));
//   EXPECT_CALL(*mockESApi, ReleaseMessage(testing::_))
//       .Times(testing::AnyNumber());
//   EXPECT_CALL(*mockESApi, RetainMessage(testing::_))
//       .WillRepeatedly(testing::Return(&esMsg));

//   SNTEndpointSecurityTamperResistance *tamperClient =
//       [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:mockESApi];

//   id mockTamperClient = OCMPartialMock(tamperClient);

//   // OCMExpect([mockTamperClient respondToMessage:OCMOCK_ANY
//   //                              withAuthResult:kv.second
//   //                                   cacheable:kv.second == ES_AUTH_RESULT_ALLOW])
//   //     .ignoringNonObjectArgs();
//   // __block es_auth_result_t gotAuthResult;
//   // __block bool gotCachable;
//   // OCMStub([mockTamperClient respondToMessage:Message(mockESApi, &esMsg)
//   //                             withAuthResult:(es_auth_result_t)0
//   //                                  cacheable:false])
//   //     .ignoringNonObjectArgs()
//   //     .andDo(^(NSInvocation *inv) {
//   //       [inv getArgument:&gotAuthResult atIndex:3];
//   //       [inv getArgument:&gotCachable atIndex:4];
//   //       printf("\n\nAND DO: %d | %d\n\n", gotAuthResult, gotCachable);
//   //     });

//   {
//     // Message msg(mockESApi, &esMsg);
//     XCTAssertThrows([tamperClient handleMessage:Message(mockESApi, &esMsg)]);
//   }

//   // {
//   //   esMsg.event_type = ES_EVENT_TYPE_AUTH_UNLINK;
//   //   for (const auto& kv : pathToResult) {
//   //     Message msg(mockESApi, &esMsg);
//   //     esMsg.event.unlink.target = kv.first;


//   //     [mockTamperClient handleMessage:std::move(msg)];

//   //     printf("\nback in tester: %d | %d\n", gotAuthResult, gotCachable);
//   //   }
//   //   // esMsg.event.unlink.target = fileEventsDB;


//   //   // esMsg.event_type == ES_EVENT_TYPE_AUTH_UNLINK
//   //   XCTAssertTrue(OCMVerifyAll(mockTamperClient));
//   // }

//   XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());

//   [mockTamperClient stopMocking];
// }

@end
