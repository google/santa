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
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
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

class MockEndpointSecurityAPI : public EndpointSecurityAPI {
public:
  MOCK_METHOD(es_message_t*, RetainMessage, (const es_message_t* msg));
  MOCK_METHOD(void, ReleaseMessage, (es_message_t* msg));
};

@interface MessageTest : XCTestCase
@end

@implementation MessageTest

- (void)setUp {
}

- (void)testConstructorsAndDestructors {
  es_file_t proc_file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&proc_file,
                                    MakeAuditToken(12, 34),
                                    MakeAuditToken(56, 78));
  es_message_t es_msg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);

  auto mock_esapi = std::make_shared<MockEndpointSecurityAPI>();

  EXPECT_CALL(*mock_esapi, ReleaseMessage(testing::_))
      .After(EXPECT_CALL(*mock_esapi, RetainMessage(testing::_))
          .WillOnce(testing::Return(&es_msg)));

  // Constructing a `Message` retains the underlying `es_message_t` and it is
  // released when the `Message` object is destructed.
  {
    auto msg = Message(mock_esapi, &es_msg);
  }

  XCTBubbleMockVerifyAndClearExpectations(mock_esapi.get());
}

- (void)testGetParentProcessName {
  // Construct a message where the parent pid is ourself
  es_file_t proc_file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&proc_file,
                                    MakeAuditToken(12, 34),
                                    MakeAuditToken(getpid(), 0));
  es_message_t es_msg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);

  auto mock_esapi = std::make_shared<MockEndpointSecurityAPI>();

  EXPECT_CALL(*mock_esapi, ReleaseMessage(testing::_))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*mock_esapi, RetainMessage(testing::_))
      .WillRepeatedly(testing::Return(&es_msg));

  // Search for an *existing* parent process.
  {
    Message msg(mock_esapi, &es_msg);

    std::string got = msg.ParentProcessName();
    std::string want = getprogname();

    XCTAssertCppStringEqual(got, want);

  }

  // Search for a *non-existent* parent process.
  {
    pid_t newPpid = AttemptToFindUnusedPID();
    proc = MakeESProcess(&proc_file,
                         MakeAuditToken(12, 34),
                         MakeAuditToken(newPpid, 34));

    Message msg(mock_esapi, &es_msg);

    std::string got = msg.ParentProcessName();
    std::string want = "";

    XCTAssertCppStringEqual(got, want);
  }
}

@end
