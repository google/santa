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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#include <dispatch/dispatch.h>
#include <memory>
#include "Source/common/TestUtils.h"

#import "Source/santad/Logs/EndpointSecurity/Writers/Spool.h"

namespace santa::santad::logs::endpoint_security::writers {

class SpoolPeer : public Spool {
 public:
  // Make constructors visible
  using Spool::Spool;

  std::string GetTypeUrl() { return type_url_; }
};

}  // namespace santa::santad::logs::endpoint_security::writers

using santa::santad::logs::endpoint_security::writers::Spool;
using santa::santad::logs::endpoint_security::writers::SpoolPeer;

@interface SpoolTest : XCTestCase
@property dispatch_queue_t q;
@property dispatch_source_t timer;
@end

@implementation SpoolTest

- (void)setUp {
  self.q = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
  XCTAssertNotNil(self.q);
  self.timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  XCTAssertNotNil(self.timer);
}

- (void)testTypeUrl {
  auto spool = std::make_shared<SpoolPeer>("/tmp", 1, 1, 1, self.q, self.timer);
  std::string wantTypeUrl("type.googleapis.com/santa.pb.v1.SantaMessage");
  XCTAssertCppStringEqual(spool->GetTypeUrl(), wantTypeUrl);
}

@end
