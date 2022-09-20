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
#include <dispatch/dispatch.h>

#include "Source/santad/Metrics.h"

namespace santa::santad {

class MetricsPeer : public Metrics {
 public:
  // Make base class constructors visible
  using Metrics::Metrics;

  bool IsRunning() { return running_; }

  uint64_t Interval() { return interval_; }
};

}  // namespace santa::santad

using santa::santad::MetricsPeer;

@interface MetricsTest : XCTestCase
@property dispatch_queue_t q;
@property dispatch_semaphore_t sema;
@property dispatch_source_t timer;
@end

@implementation MetricsTest

- (void)setUp {
  self.q = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
  XCTAssertNotNil(self.q);
  self.timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  XCTAssertNotNil(self.timer);
  self.sema = dispatch_semaphore_create(0);
}

- (void)testStartStop {
  auto metrics = std::make_shared<MetricsPeer>(nil, self.q, self.timer, 100, ^{
    dispatch_semaphore_signal(self.sema);
  });

  XCTAssertFalse(metrics->IsRunning());

  metrics->StartPoll();
  XCTAssertEqual(0, dispatch_semaphore_wait(self.sema, DISPATCH_TIME_NOW),
                 "Initialization block never called");

  // Should be marked running after starting
  XCTAssertTrue(metrics->IsRunning());

  metrics->StartPoll();

  // Ensure the initialization block isn't called a second time
  XCTAssertNotEqual(0, dispatch_semaphore_wait(self.sema, DISPATCH_TIME_NOW),
                    "Initialization block called second time unexpectedly");

  // Double-start doesn't change the running state
  XCTAssertTrue(metrics->IsRunning());

  metrics->StopPoll();

  // After stopping, the internal state is no longer marked running
  XCTAssertFalse(metrics->IsRunning());

  metrics->StopPoll();

  // Double-stop doesn't change the running state
  XCTAssertFalse(metrics->IsRunning());
}

- (void)testSetInterval {
  auto metrics = std::make_shared<MetricsPeer>(nil, self.q, self.timer, 100,
                                               ^{
                                               });

  XCTAssertEqual(100, metrics->Interval());

  metrics->SetInterval(200);
  XCTAssertEqual(200, metrics->Interval());
}

@end
