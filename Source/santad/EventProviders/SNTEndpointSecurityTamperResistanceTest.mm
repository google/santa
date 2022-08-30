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

static constexpr std::string_view kEventsDBPath = "/private/var/db/santa/events.db";
static constexpr std::string_view kRulesDBPath = "/private/var/db/santa/rules.db";
static constexpr std::string_view kBenignPath = "/some/other/path";
static constexpr std::string_view kSantaKextIdentifier = "com.google.santa-driver";

@interface SNTEndpointSecurityTamperResistanceTest : XCTestCase
@end

@implementation SNTEndpointSecurityTamperResistanceTest

- (void)testEnable {
  // Ensure the client subscribes to expected event types
  std::set<es_event_type_t> expectedEventSubs{
      ES_EVENT_TYPE_AUTH_KEXTLOAD,
      ES_EVENT_TYPE_AUTH_UNLINK,
      ES_EVENT_TYPE_AUTH_RENAME,
      };

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();

  SNTEndpointSecurityTamperResistance* tamperClient =
      [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:mockESApi
                                                          logger:nullptr];
  id mockTamperClient = OCMPartialMock(tamperClient);

  [mockTamperClient enable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  [mockTamperClient stopMocking];
}

- (void)testHandleMessage {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file, {}, {});
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth);

  es_file_t fileEventsDB = MakeESFile(kEventsDBPath.data());
  es_file_t fileRulesDB = MakeESFile(kRulesDBPath.data());
  es_file_t fileBenign = MakeESFile(kBenignPath.data());

  es_string_token_t santaTok = MakeESStringToken(kSantaKextIdentifier.data());
  es_string_token_t benignTok = MakeESStringToken(kBenignPath.data());

  std::map<es_file_t*, es_auth_result_t> pathToResult {
    { &fileEventsDB, ES_AUTH_RESULT_DENY },
    { &fileRulesDB, ES_AUTH_RESULT_DENY },
    { &fileBenign, ES_AUTH_RESULT_ALLOW },
  };

  std::map<es_string_token_t*, es_auth_result_t> kextIdToResult {
    { &santaTok, ES_AUTH_RESULT_DENY },
    { &benignTok, ES_AUTH_RESULT_ALLOW },
  };

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage(&esMsg);

  SNTEndpointSecurityTamperResistance *tamperClient =
      [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:mockESApi logger:nullptr];

  id mockTamperClient = OCMPartialMock(tamperClient);

  // Unable to use `OCMExpect` here because we cannot match on the `Message`
  // parameter. In order to verify the `AuthResult` and `Cacheable` parameters,
  // instead use `OCMStub` and extract the arguments in order to assert their
  // expected values.
  __block es_auth_result_t gotAuthResult;
  __block bool gotCachable;
  OCMStub([mockTamperClient respondToMessage:Message(mockESApi, &esMsg)
                              withAuthResult:(es_auth_result_t)0
                                   cacheable:false])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation *inv) {
        [inv getArgument:&gotAuthResult atIndex:3];
        [inv getArgument:&gotCachable atIndex:4];
      });

  // First check unhandled event types will crash
  {
    Message msg(mockESApi, &esMsg);
    XCTAssertThrows([tamperClient handleMessage:Message(mockESApi, &esMsg)]);
  }

  // Check UNLINK tamper events
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_UNLINK;
    for (const auto& kv : pathToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.unlink.target = kv.first;


      [mockTamperClient handleMessage:std::move(msg)];

      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check RENAME `source` tamper events
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_RENAME;
    for (const auto& kv : pathToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.rename.source = kv.first;
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;

      [mockTamperClient handleMessage:std::move(msg)];

      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check RENAME `dest` tamper events
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_RENAME;
    esMsg.event.rename.source = &fileBenign;
    for (const auto& kv : pathToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
      esMsg.event.rename.destination.existing_file = kv.first;

      [mockTamperClient handleMessage:std::move(msg)];

      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check KEXTLOAD tamper events
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_KEXTLOAD;

    for (const auto& kv : kextIdToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.kextload.identifier = *kv.first;

      [mockTamperClient handleMessage:std::move(msg)];

      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, true); // Note: Kext responses always cached
    }
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTAssertTrue(OCMVerifyAll(mockTamperClient));

  [mockTamperClient stopMocking];
}

@end
