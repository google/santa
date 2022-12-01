/// Copyright 2022 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include "Source/santad/EventProviders/SNTEndpointSecurityWatcher.h"

#include <EndpointSecurity/ESTypes.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <cstddef>
#include <variant>

#include "Source/common/TestUtils.h"
#include "Source/common/Unit.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"

using santa::common::Unit;
using santa::santad::event_providers::endpoint_security::Message;

using PathTargets = std::pair<std::string_view, std::variant<std::string_view, std::string, Unit>>;
extern PathTargets GetPathTargets(const Message &msg);

@interface SNTEndpointSecurityWatcherTest : XCTestCase
@end

@implementation SNTEndpointSecurityWatcherTest

- (void)testEnable {
  std::set<es_event_type_t> expectedEventSubs{
    ES_EVENT_TYPE_AUTH_OPEN,   ES_EVENT_TYPE_AUTH_LINK,  ES_EVENT_TYPE_AUTH_RENAME,
    ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_AUTH_CLONE, ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
  };

#if defined(MAC_OS_VERSION_12_0) && MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_VERSION_12_0
  if (@available(macOS 12.0, *)) {
    expectedEventSubs.insert(ES_EVENT_TYPE_AUTH_COPYFILE);
  }
#endif

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  id watcherClient =
    [[SNTEndpointSecurityWatcher alloc] initWithESAPI:mockESApi
                                              metrics:nullptr
                                            processor:santa::santad::Processor::kWatcher];

  EXPECT_CALL(*mockESApi, ClearCache)
    .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
             .WillOnce(testing::Return(true)))
    .WillOnce(testing::Return(true));

  [watcherClient enable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testGetPathTargets {
  // This test ensures that the `GetPathTargets` functions returns the
  // expected combination of targets for each handled event variant
  es_file_t testFile1 = MakeESFile("test_file_1");
  es_file_t testFile2 = MakeESFile("test_file_2");
  es_file_t testDir = MakeESFile("test_dir");
  es_string_token_t testTok = MakeESStringToken("test_tok");
  std::string dirTok = std::string(testDir.path.data) + std::string(testTok.data);

  es_message_t esMsg;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  Message msg(mockESApi, &esMsg);

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_OPEN;
    esMsg.event.open.file = &testFile1;

    PathTargets targets = GetPathTargets(msg);

    XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
    XCTAssertTrue(std::holds_alternative<Unit>(targets.second));
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_LINK;
    esMsg.event.link.source = &testFile1;
    esMsg.event.link.target_dir = &testDir;
    esMsg.event.link.target_filename = testTok;

    PathTargets targets = GetPathTargets(msg);

    XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
    XCTAssertTrue(std::holds_alternative<std::string>(targets.second));
    XCTAssertCppStringEqual(std::get<std::string>(targets.second), dirTok);
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_RENAME;
    esMsg.event.rename.source = &testFile1;

    {
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
      esMsg.event.rename.destination.existing_file = &testFile2;

      PathTargets targets = GetPathTargets(msg);

      XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
      XCTAssertTrue(std::holds_alternative<std::string_view>(targets.second));
      XCTAssertCStringEqual(std::get<std::string_view>(targets.second).data(), testFile2.path.data);
    }

    {
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
      esMsg.event.rename.destination.new_path.dir = &testDir;
      esMsg.event.rename.destination.new_path.filename = testTok;

      PathTargets targets = GetPathTargets(msg);

      XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
      XCTAssertTrue(std::holds_alternative<std::string>(targets.second));
      XCTAssertCppStringEqual(std::get<std::string>(targets.second), dirTok);
    }
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_UNLINK;
    esMsg.event.unlink.target = &testFile1;

    PathTargets targets = GetPathTargets(msg);

    XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
    XCTAssertTrue(std::holds_alternative<Unit>(targets.second));
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_CLONE;
    esMsg.event.clone.source = &testFile1;
    esMsg.event.clone.target_dir = &testDir;
    esMsg.event.clone.target_name = testTok;

    PathTargets targets = GetPathTargets(msg);

    XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
    XCTAssertTrue(std::holds_alternative<std::string>(targets.second));
    XCTAssertCppStringEqual(std::get<std::string>(targets.second), dirTok);
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_EXCHANGEDATA;
    esMsg.event.exchangedata.file1 = &testFile1;
    esMsg.event.exchangedata.file2 = &testFile2;

    PathTargets targets = GetPathTargets(msg);

    XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
    XCTAssertTrue(std::holds_alternative<std::string_view>(targets.second));
    XCTAssertCStringEqual(std::get<std::string_view>(targets.second).data(), testFile2.path.data);
  }

  if (@available(macOS 12.0, *)) {
    {
      esMsg.event_type = ES_EVENT_TYPE_AUTH_COPYFILE;
      esMsg.event.copyfile.source = &testFile1;
      esMsg.event.copyfile.target_dir = &testDir;
      esMsg.event.copyfile.target_name = testTok;

      {
        esMsg.event.copyfile.target_file = nullptr;

        PathTargets targets = GetPathTargets(msg);

        XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
        XCTAssertTrue(std::holds_alternative<std::string>(targets.second));
        XCTAssertCppStringEqual(std::get<std::string>(targets.second), dirTok);
      }

      {
        esMsg.event.copyfile.target_file = &testFile2;

        PathTargets targets = GetPathTargets(msg);

        XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
        XCTAssertTrue(std::holds_alternative<std::string_view>(targets.second));
        XCTAssertCStringEqual(std::get<std::string_view>(targets.second).data(),
                              testFile2.path.data);
      }
    }
  }
}

@end
