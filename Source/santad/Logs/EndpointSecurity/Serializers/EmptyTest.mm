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

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Empty.h"

using santa::Empty;

@interface EmptyTest : XCTestCase
@end

@implementation EmptyTest

- (void)testAllSerializersReturnEmptyVector {
  std::shared_ptr<Empty> e = Empty::Create();

  // We can get away with passing a fake argument to the `Serialize*` methods
  // instead of constructing real ones since the Empty class never touches the
  // input parameter.
  int fake;
  XCTAssertEqual(e->SerializeMessage(*(santa::EnrichedClose *)&fake).size(), 0);
  XCTAssertEqual(e->SerializeMessage(*(santa::EnrichedExchange *)&fake).size(), 0);
  XCTAssertEqual(e->SerializeMessage(*(santa::EnrichedExec *)&fake, nil).size(), 0);
  XCTAssertEqual(e->SerializeMessage(*(santa::EnrichedExit *)&fake).size(), 0);
  XCTAssertEqual(e->SerializeMessage(*(santa::EnrichedFork *)&fake).size(), 0);
  XCTAssertEqual(e->SerializeMessage(*(santa::EnrichedLink *)&fake).size(), 0);
  XCTAssertEqual(e->SerializeMessage(*(santa::EnrichedRename *)&fake).size(), 0);
  XCTAssertEqual(e->SerializeMessage(*(santa::EnrichedUnlink *)&fake).size(), 0);
  XCTAssertEqual(e->SerializeMessage(*(santa::EnrichedCSInvalidated *)&fake).size(), 0);

  XCTAssertEqual(e->SerializeAllowlist(*(santa::Message *)&fake, "").size(), 0);
  XCTAssertEqual(e->SerializeBundleHashingEvent(nil).size(), 0);
  XCTAssertEqual(e->SerializeDiskAppeared(nil).size(), 0);
  XCTAssertEqual(e->SerializeDiskDisappeared(nil).size(), 0);
}

@end
