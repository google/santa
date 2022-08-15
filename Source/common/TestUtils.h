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

#ifndef SANTA__COMMON__TESTUTILS_H
#define SANTA__COMMON__TESTUTILS_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <time.h>
#import <XCTest/XCTest.h>

#define NOBODY_UID ((unsigned int)-2)
#define NOBODY_GID ((unsigned int)-2)

// Bubble up googletest expectation failures to XCTest failures
#define XCTBubbleMockVerifyAndClearExpectations(mock) \
    XCTAssertTrue(::testing::Mock::VerifyAndClearExpectations(mock), \
                  "Expected calls were not properly mocked")

// Pretty print C++ string match errors
#define XCTAssertCppStringEqual(got, want) \
    XCTAssertTrue((got) == (want), \
                   "\nMismatched strings.\n\t got: %s\n\twant: %s", \
                   (got).c_str(), \
                   (want).c_str())

// Helper to ensure at least `ms` milliseconds are slept, even if the sleep
// function returns early due to interrupts.
static inline void SleepMS(long ms) {
  // Wait for the item to expire
  struct timespec ts {
    .tv_sec = 0,
    .tv_nsec = (long)(ms * NSEC_PER_MSEC),
  };

  while (nanosleep(&ts, &ts) != 0) {
    XCTAssertEqual(errno, EINTR);
  }
}

#endif
