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

#include "Source/santad/EventProviders/RateLimiter.h"

#include <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include "Source/common/SystemResources.h"
#include "Source/santad/Metrics.h"

using santa::RateLimiter;

static const santa::Processor kDefaultProcessor = santa::Processor::kFileAccessAuthorizer;

namespace santa {

class RateLimiterPeer : public RateLimiter {
 public:
  using RateLimiter::RateLimiter;

  using RateLimiter::EventsRateLimitedLocked;
  using RateLimiter::ShouldRateLimitLocked;
  using RateLimiter::TryResetLocked;

  using RateLimiter::log_count_total_;
  using RateLimiter::reset_mach_time_;
};

}  // namespace santa

using santa::RateLimiterPeer;

@interface RateLimiterTest : XCTestCase
@end

@implementation RateLimiterTest

- (void)testTryResetLocked {
  // Create an object supporting 1 QPS, and a reset duration of 2s
  uint16_t maxQps = 1;
  NSTimeInterval resetDuration = 2;
  RateLimiterPeer rlp(nullptr, kDefaultProcessor, maxQps, resetDuration);

  // Check the current reset_mach_time_ is 0 so that it gets
  // set when the first decision is made
  XCTAssertEqual(rlp.reset_mach_time_, 0);

  // Define our current mach time and create the expected new reset duration floor
  uint64_t curMachTime = 1;
  uint64_t expectedMachTime = AddNanosecondsToMachTime(resetDuration, curMachTime);

  // Set a higher log count to ensure it is reset
  rlp.log_count_total_ = 123;

  rlp.TryResetLocked(curMachTime);

  // Ensure values are reset appropriately
  XCTAssertEqual(rlp.log_count_total_, 0);
  XCTAssertGreaterThanOrEqual(rlp.reset_mach_time_, expectedMachTime);

  // Setup values so that calling TryResetLocked shouldn't reset anything
  size_t expectedLogCount = 123;
  expectedMachTime = 456;
  rlp.log_count_total_ = expectedLogCount;
  rlp.reset_mach_time_ = expectedMachTime;
  curMachTime = rlp.reset_mach_time_;

  rlp.TryResetLocked(curMachTime);

  // Ensure the values were not changed
  XCTAssertEqual(rlp.log_count_total_, expectedLogCount);
  XCTAssertGreaterThanOrEqual(rlp.reset_mach_time_, expectedMachTime);
}

- (void)testDecide {
  // Create an object supporting 2 QPS, and a reset duration of 4s
  uint16_t maxQps = 2;
  NSTimeInterval resetDuration = 4;
  uint64_t allowedLogsPerDuration = maxQps * resetDuration;
  RateLimiterPeer rlp(nullptr, kDefaultProcessor, maxQps, resetDuration);

  // Check the current log count is initially 0
  XCTAssertEqual(rlp.log_count_total_, 0);

  // Make the first decision
  RateLimiter::Decision gotDecision;

  for (uint64_t i = 0; i < (allowedLogsPerDuration); i++) {
    gotDecision = rlp.Decide(0);
    XCTAssertEqual(gotDecision, RateLimiter::Decision::kAllowed);
  }

  // Ensure the log count is the expected amount
  XCTAssertEqual(rlp.log_count_total_, allowedLogsPerDuration);

  // Make another decision and ensure the log count still increases and
  // the decision is rate limited
  gotDecision = rlp.Decide(0);
  XCTAssertEqual(gotDecision, RateLimiter::Decision::kRateLimited);
  XCTAssertEqual(rlp.log_count_total_, allowedLogsPerDuration + 1);

  // Make another decision, though now with the cur mach time greater than
  // the reset mach time. Then ensure values were appropriately reset.
  uint64_t oldResetMachTime = rlp.reset_mach_time_;
  gotDecision = rlp.Decide(rlp.reset_mach_time_ + 1);
  XCTAssertEqual(gotDecision, RateLimiter::Decision::kAllowed);
  XCTAssertEqual(rlp.log_count_total_, 1);
  XCTAssertGreaterThan(rlp.reset_mach_time_, oldResetMachTime);
}

- (void)testShouldRateLimitAndCounts {
  // Create an object supporting 2 QPS, and a reset duration of 4s
  uint16_t maxQps = 2;
  NSTimeInterval resetDuration = 4;
  uint64_t allowedLogsPerDuration = maxQps * resetDuration;
  uint64_t logsOverQPS = 5;
  RateLimiterPeer rlp(nullptr, kDefaultProcessor, maxQps, resetDuration);

  // Initially no rate limiting should apply
  XCTAssertFalse(rlp.ShouldRateLimitLocked());
  XCTAssertEqual(rlp.EventsRateLimitedLocked(), 0);

  // Simulate a smmaller volume of logs received than QPS
  rlp.log_count_total_ = allowedLogsPerDuration - 1;

  XCTAssertFalse(rlp.ShouldRateLimitLocked());
  XCTAssertEqual(rlp.EventsRateLimitedLocked(), 0);

  // Simulate a larger volume of logs received than QPS
  rlp.log_count_total_ = allowedLogsPerDuration + logsOverQPS;

  XCTAssertTrue(rlp.ShouldRateLimitLocked());
  XCTAssertEqual(rlp.EventsRateLimitedLocked(), logsOverQPS);
}

@end
