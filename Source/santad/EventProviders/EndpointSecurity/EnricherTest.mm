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

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"

using santa::santad::event_providers::endpoint_security::Enricher;

@interface EnricherTest : XCTestCase
@end

@implementation EnricherTest

- (void)testUidGid {
  Enricher enricher;

  auto user = enricher.UsernameForUID(NOBODY_UID);
  XCTAssertTrue(user.has_value());
  XCTAssertEqual(strcmp(user->get()->c_str(), "nobody"), 0);

  auto group = enricher.UsernameForGID(NOBODY_GID);
  XCTAssertTrue(group.has_value());
  XCTAssertEqual(strcmp(group->get()->c_str(), "nobody"), 0);

  auto invalid_uid = (uid_t)-123;
  auto invalid_gid = (gid_t)-123;

  auto invalid_user = enricher.UsernameForUID(invalid_uid);
  XCTAssertFalse(invalid_user.has_value());

  auto invalid_group = enricher.UsernameForGID(invalid_gid);
  XCTAssertFalse(invalid_group.has_value());
}

@end
