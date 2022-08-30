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
#import <XCTest/XCTest.h>

#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Utilities.h"

using santa::santad::event_providers::endpoint_security::Message;

@interface SerializerUtilitiesTest : XCTestCase
@end

@implementation SerializerUtilitiesTest

- (void)testSanitizeString {
  NSString *empty = @"";
  NSString *noSanitize = @"nothing_to_sanitize";

  // Intentional pointer compare. String with no replacement and
  // 0-length strings return the original object.
  XCTAssertEqual(empty, sanitizeString(empty));
  XCTAssertEqual(noSanitize, sanitizeString(noSanitize));

  XCTAssertEqualObjects(sanitizeString(@"|"), @"<pipe>");
  XCTAssertEqualObjects(sanitizeString(@"\n"), @"\\n");
  XCTAssertEqualObjects(sanitizeString(@"\r"), @"\\r");

  XCTAssertEqualObjects(sanitizeString(@"a\nb\rc|"), @"a\\nb\\rc<pipe>");

  XCTAssertEqualObjects(sanitizeString(@"a|trailing"), @"a<pipe>trailing");

  // Create a long string to trigger the malloc path
  NSString *base = [NSString stringWithFormat:@"%@|abc",
                              [@"" stringByPaddingToLength:66*1024
                                                withString:@"A"
                                           startingAtIndex:0]];

  NSString *want = [NSString stringWithFormat:@"%@<pipe>abc",
                              [@"" stringByPaddingToLength:66*1024
                                                withString:@"A"
                                           startingAtIndex:0]];

  NSString *got = sanitizeString(base);
  XCTAssertEqualObjects(got, want);
}

- (void)testGetAllowListTargetFile {
  es_file_t closeTargetFile = MakeESFile("close_target");
  es_file_t renameSourceFile = MakeESFile("rename_source");
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile, {}, {});
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE,
                                     &proc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage(&esMsg);

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

@end
