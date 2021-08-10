/// Copyright 2021 Google Inc. All rights reserved.
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
#import <XCTest/XCTest.h>
#import <bsm/libbsm.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityManager.h"

// Must be imported last to overload libEndpointSecurity functions.
#import "Source/santad/EventProviders/EndpointSecurityTestUtil.h"

const NSString *const kEventsDBPath = @"/private/var/db/santa/events.db";
const NSString *const kRulesDBPath = @"/private/var/db/santa/rules.db";

@interface SNTEndpointSecurityManagerTest : XCTestCase
@end

@implementation SNTEndpointSecurityManagerTest

- (void)setUp {
  [super setUp];
  fclose(stdout);
}

- (void)testDenyOnTimeout {
  // There should be two events: an early uncached DENY as the consequence for not
  // meeting the decision deadline and an actual cached decision from our message
  // handler.
  __block int wantNumResp = 2;

  MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
  [mockES reset];
  SNTEndpointSecurityManager *snt = [[SNTEndpointSecurityManager alloc] init];

  XCTestExpectation *expectation =
    [self expectationWithDescription:@"Wait for santa's Auth dispatch queue"];

  __block NSMutableArray<ESResponse *> *events = [NSMutableArray array];
  [mockES registerResponseCallback:^(ESResponse *r) {
    @synchronized(self) {
      [events addObject:r];
    }

    if (events.count >= wantNumResp) {
      [expectation fulfill];
    }
  }];

  es_file_t dbFile = {.path = MakeStringToken(kEventsDBPath)};
  es_file_t otherBinary = {.path = MakeStringToken(@"somebinary")};
  es_process_t proc = {
    .executable = &otherBinary,
    .is_es_client = false,
    .codesigning_flags = 570509313,
    .session_id = 12345,
    .group_id = 12345,
    .ppid = 12345,
    .original_ppid = 12345,
    .is_platform_binary = false,
  };
  es_event_unlink_t unlink_event = {.target = &dbFile};
  es_events_t event = {.unlink = unlink_event};
  es_message_t m = {
    .version = 4,
    .event_type = ES_EVENT_TYPE_AUTH_UNLINK,
    .event = event,
    .mach_time = DISPATCH_TIME_NOW,
    .action_type = ES_ACTION_TYPE_AUTH,
    .deadline = DISPATCH_TIME_NOW,
    .process = &proc,
    .seq_num = 1337,
  };

  [mockES triggerHandler:&m];

  [self waitForExpectationsWithTimeout:10.0
                               handler:^(NSError *error) {
                                 if (error) {
                                   XCTFail(@"Santa auth test timed out without receiving two "
                                           @"events. Instead, had error: %@",
                                           error);
                                 }
                               }];

  for (ESResponse *resp in events) {
    XCTAssertEqual(
      resp.result, ES_AUTH_RESULT_DENY,
      @"Failed to automatically deny on timeout and also the malicious event afterwards");
  }
}

- (void)testDeleteRulesDB {
  for (const NSString *testPath in @[ kEventsDBPath, kRulesDBPath ]) {
    MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
    [mockES reset];
    SNTEndpointSecurityManager *snt = [[SNTEndpointSecurityManager alloc] init];

    XCTestExpectation *expectation = [self expectationWithDescription:@"Wait for response from ES"];
    __block ESResponse *got = nil;
    [mockES registerResponseCallback:^(ESResponse *r) {
      got = r;
      [expectation fulfill];
    }];

    es_file_t dbFile = {.path = MakeStringToken(testPath)};
    es_file_t otherBinary = {.path = MakeStringToken(@"somebinary")};
    es_process_t proc = {
      .executable = &otherBinary,
      .is_es_client = false,
      .codesigning_flags = 570509313,
      .session_id = 12345,
      .group_id = 12345,
      .ppid = 12345,
      .original_ppid = 12345,
      .is_platform_binary = false,
    };
    es_event_unlink_t unlink_event = {.target = &dbFile};
    es_events_t event = {.unlink = unlink_event};
    es_message_t m = {
      .version = 4,
      .event_type = ES_EVENT_TYPE_AUTH_UNLINK,
      .event = event,
      .mach_time = DISPATCH_TIME_NOW,
      .action_type = ES_ACTION_TYPE_AUTH,
      .deadline = DISPATCH_TIME_FOREVER,
      .process = &proc,
      .seq_num = 1337,
    };
    [mockES triggerHandler:&m];

    [self waitForExpectationsWithTimeout:10.0
                                 handler:^(NSError *error) {
                                   if (error) {
                                     XCTFail(@"Santa auth test timed out with error: %@", error);
                                   }
                                 }];

    XCTAssertEqual(got.result, ES_AUTH_RESULT_DENY, @"Failed to deny deletion of %@", testPath);
    XCTAssertTrue(got.shouldCache, @"Failed to cache deletion decision of %@", testPath);
  }
}

- (void)testSkipOtherESEvents {
  MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
  [mockES reset];
  SNTEndpointSecurityManager *snt = [[SNTEndpointSecurityManager alloc] init];

  XCTestExpectation *expectation = [self expectationWithDescription:@"Wait for response from ES"];

  __block ESResponse *got = nil;
  [mockES registerResponseCallback:^(ESResponse *r) {
    got = r;
    [expectation fulfill];
  }];

  es_file_t dbFile = {.path = MakeStringToken(kEventsDBPath)};
  es_file_t otherBinary = {.path = MakeStringToken(@"somebinary")};
  es_process_t proc = {
    .executable = &otherBinary,
    .is_es_client = true,
    .codesigning_flags = 570509313,
    .session_id = 12345,
    .group_id = 12345,
    .ppid = 12345,
    .original_ppid = 12345,
    .is_platform_binary = false,
  };
  es_event_unlink_t unlink_event = {.target = &dbFile};
  es_events_t event = {.unlink = unlink_event};
  es_message_t m = {
    .version = 4,
    .event_type = ES_EVENT_TYPE_AUTH_UNLINK,
    .event = event,
    .mach_time = DISPATCH_TIME_NOW,
    .action_type = ES_ACTION_TYPE_AUTH,
    .deadline = DISPATCH_TIME_FOREVER,
    .process = &proc,
    .seq_num = 1337,
  };

  [mockES triggerHandler:&m];
  [self waitForExpectationsWithTimeout:10.0
                               handler:^(NSError *error) {
                                 if (error) {
                                   XCTFail(@"Santa auth test timed out with error: %@", error);
                                 }
                               }];

  XCTAssertEqual(got.result, ES_AUTH_RESULT_ALLOW);
  XCTAssertEqual(got.shouldCache, false);
}

@end
