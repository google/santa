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

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#include <memory>

#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Utilities.h"

using santa::santad::event_providers::endpoint_security::Message;
using santa::GetAllowListTargetFile;
using santa::MountFromName;

@interface UtilitiesTest : XCTestCase
@end

@implementation UtilitiesTest

- (void)testGetAllowListTargetFile {
  es_file_t closeTargetFile = MakeESFile("close_target");
  es_file_t renameSourceFile = MakeESFile("rename_source");
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &proc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  {
    esMsg.event.close.target = &closeTargetFile;
    Message msg(mockESApi, &esMsg);
    es_file_t *target = GetAllowListTargetFile(msg);
    XCTAssertEqual(target, &closeTargetFile);
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_NOTIFY_RENAME;
    esMsg.event.rename.source = &renameSourceFile;
    Message msg(mockESApi, &esMsg);
    es_file_t *target = GetAllowListTargetFile(msg);
    XCTAssertEqual(target, &renameSourceFile);
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_NOTIFY_EXIT;
    Message msg(mockESApi, &esMsg);
    XCTAssertThrows(GetAllowListTargetFile(msg));
  }
}

- (void)testMountFromName {
  XCTAssertNil(MountFromName(@""));
  XCTAssertNil(MountFromName(nil));
  XCTAssertNil(MountFromName(@"./this/path/should/not/ever/exist/"));

  XCTAssertCppStringBeginsWith(std::string(MountFromName(@"/").UTF8String), std::string("/"));
}

@end
