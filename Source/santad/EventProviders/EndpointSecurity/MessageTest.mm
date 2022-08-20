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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <libproc.h>
#import <OCMock/OCMock.h>
#include <stdlib.h>
#import <XCTest/XCTest.h>

#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"

using santa::santad::event_providers::endpoint_security::Message;

bool IsPidInUse(pid_t pid) {
  char pname[MAXCOMLEN * 2 + 1] = {};
  errno = 0;
  if (proc_name(pid, pname, sizeof(pname)) <= 0 && errno == ESRCH) {
    return false;
  }

  // The PID may or may not actually be in use, but assume it is
  return true;
}

// Try to find an unused PID by looking for libproc returning ESRCH errno.
// Start searching backwards from PID_MAX to increase likelyhood that the
// returned PID will still be unused by the time it's being used.
// TODO(mlw): Alternatively, we could inject the `proc_name` function into
// the `Message` object to remove the guesswork here.
pid_t AttemptToFindUnusedPID() {
  for (pid_t pid = 99999 /* PID_MAX */; pid > 1; pid--) {
    if (!IsPidInUse(pid)) {
      return pid;
    }
  }

  return 0;
}

@interface MessageTest : XCTestCase
@end

@implementation MessageTest

- (void)setUp {
}

- (void)testConstructorsAndDestructors {
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile,
                                    MakeAuditToken(12, 34),
                                    MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);

  auto mock_esapi = std::make_shared<MockEndpointSecurityAPI>();

  EXPECT_CALL(*mock_esapi, ReleaseMessage(testing::_))
      .After(EXPECT_CALL(*mock_esapi, RetainMessage(testing::_))
          .WillOnce(testing::Return(&esMsg)));

  // Constructing a `Message` retains the underlying `es_message_t` and it is
  // released when the `Message` object is destructed.
  {
    auto msg = Message(mock_esapi, &esMsg);
  }

  XCTBubbleMockVerifyAndClearExpectations(mock_esapi.get());
}

- (void)testCopyConstructor {
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile,
                                    MakeAuditToken(12, 34),
                                    MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, ReleaseMessage(testing::_))
      .Times(2)
      .After(
          EXPECT_CALL(*mockESApi, RetainMessage(testing::_))
              .Times(2)
              .WillRepeatedly(testing::Return(&esMsg)));

  {
    Message msg1(mockESApi, &esMsg);
    Message msg2(msg1);

    // Both messages should now point to the same `es_message_t`
    XCTAssertEqual(msg1.operator->(), &esMsg);
    XCTAssertEqual(msg2.operator->(), &esMsg);
  }

  // Ensure the retain/release mocks were called the expected number of times
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testGetParentProcessName {
  // Construct a message where the parent pid is ourself
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile,
                                    MakeAuditToken(12, 34),
                                    MakeAuditToken(getpid(), 0));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);

  auto mock_esapi = std::make_shared<MockEndpointSecurityAPI>();

  EXPECT_CALL(*mock_esapi, ReleaseMessage(testing::_))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*mock_esapi, RetainMessage(testing::_))
      .WillRepeatedly(testing::Return(&esMsg));

  // Search for an *existing* parent process.
  {
    Message msg(mock_esapi, &esMsg);

    std::string got = msg.ParentProcessName();
    std::string want = getprogname();

    XCTAssertCppStringEqual(got, want);

  }

  // Search for a *non-existent* parent process.
  {
    pid_t newPpid = AttemptToFindUnusedPID();
    proc = MakeESProcess(&procFile,
                         MakeAuditToken(12, 34),
                         MakeAuditToken(newPpid, 34));

    Message msg(mock_esapi, &esMsg);

    std::string got = msg.ParentProcessName();
    std::string want = "";

    XCTAssertCppStringEqual(got, want);
  }
}

@end
