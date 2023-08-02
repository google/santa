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

#include <EndpointSecurity/EndpointSecurity.h>
#import <XCTest/XCTest.h>
#include <bsm/libbsm.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/stat.h>

#define NOBODY_UID ((unsigned int)-2)
#define NOGROUP_GID ((unsigned int)-1)

// Bubble up googletest expectation failures to XCTest failures
#define XCTBubbleMockVerifyAndClearExpectations(mock)              \
  XCTAssertTrue(::testing::Mock::VerifyAndClearExpectations(mock), \
                "Expected calls were not properly mocked")

// Pretty print C string match errors
#define XCTAssertCStringEqual(got, want)                                                      \
  XCTAssertTrue(strcmp((got), (want)) == 0, @"\nMismatched strings.\n\t got: %s\n\twant: %s", \
                (got), (want))

// Pretty print C++ string match errors
#define XCTAssertCppStringEqual(got, want) XCTAssertCStringEqual((got).c_str(), (want).c_str())

// Note: Delta between local formatter and the one run on Github. Disable for now.
// clang-format off
#define XCTAssertSemaTrue(s, sec, m) \
  XCTAssertEqual(                    \
    0, dispatch_semaphore_wait((s), dispatch_time(DISPATCH_TIME_NOW, (sec) * NSEC_PER_SEC)), m)
// clang-format on

// Helper to ensure at least `ms` milliseconds are slept, even if the sleep
// function returns early due to interrupts.
void SleepMS(long ms);

// Helper to construct strings of a given length
NSString *RepeatedString(NSString *str, NSUInteger len);

//
// Helpers to construct various ES structs
//

enum class ActionType {
  Auth,
  Notify,
};

audit_token_t MakeAuditToken(pid_t pid, pid_t pidver);

/// Construct a `struct stat` buffer with each member having a unique value.
/// @param offset An optional offset to be added to each member. useful when
///   a test has multiple stats and you'd like for them each to have different
///   values across the members.
struct stat MakeStat(int offset = 0);

es_string_token_t MakeESStringToken(const char *s);
es_file_t MakeESFile(const char *path, struct stat sb = {});
es_process_t MakeESProcess(es_file_t *file, audit_token_t tok = {}, audit_token_t parent_tok = {});
es_message_t MakeESMessage(es_event_type_t et, es_process_t *proc,
                           ActionType action_type = ActionType::Notify,
                           uint64_t future_deadline_ms = 100000);

uint32_t MaxSupportedESMessageVersionForCurrentOS();

#endif
