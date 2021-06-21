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
@property SNTEndpointSecurityManager *snt;
@end

@implementation SNTEndpointSecurityManagerTest

- (void)setUp {
  [super setUp];
  fclose(stdout);
}

- (void)testDeleteRulesDB {
  __block int wantNumResp = 2;

  MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
  [mockES reset];
  SNTEndpointSecurityManager *snt = [[SNTEndpointSecurityManager alloc] init];

  [snt setLogCallback:^(santa_message_t m) {
    return;
  }];
  [snt setDecisionCallback:^(santa_message_t m) {
    return;
  }];

  XCTestExpectation *expectation =
    [self expectationWithDescription:@"Wait for santa's Auth dispatch queue"];

  __block NSMutableArray<ESResponse *> *events = [NSMutableArray array];
  [mockES registerResponseCallback:^(ESResponse *r) {
    @synchronized(self) {
      [events addObject:r];
    }

    if ([events count] >= wantNumResp) {
      [expectation fulfill];
    }
  }];

  es_file_t dbFile = {.path = MakeStringToken(kRulesDBPath)};
  es_file_t otherBinary = {.path = MakeStringToken(@"somebinary")};
  es_process_t proc = {
    .executable = &otherBinary,
    .is_es_client = false,
  };
  es_event_unlink_t unlink_event = {.target = &dbFile};
  es_events_t event = {.unlink = unlink_event};
  es_message_t m = {
    .event_type = ES_EVENT_TYPE_AUTH_UNLINK,
    .event = event,
    .action_type = ES_ACTION_TYPE_AUTH,
    .deadline = DISPATCH_TIME_NOW + NSEC_PER_SEC * 60,
    .process = &proc,
  };
  [mockES triggerHandler:&m];

  [self waitForExpectationsWithTimeout:10.0
                               handler:^(NSError *error) {
                                 if (error) {
                                   XCTFail(@"Santa auth test timed out with error: %@", error);
                                 }
                               }];
}

- (void)testSkipOtherESEvents {
  MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
  [mockES reset];
  SNTEndpointSecurityManager *snt = [[SNTEndpointSecurityManager alloc] init];

  [snt setLogCallback:^(santa_message_t m) {
    return;
  }];
  [snt setDecisionCallback:^(santa_message_t m) {
    return;
  }];

  __block NSMutableArray<ESResponse *> *events = [NSMutableArray array];
  [mockES registerResponseCallback:^(ESResponse *r) {
    @synchronized(self) {
      [events addObject:r];
    }
  }];

  es_file_t otherBinary = {.path = MakeStringToken(@"somebinary")};
  es_process_t proc = {.executable = &otherBinary, .is_es_client = true};
  es_message_t m = {
    .action_type = ES_ACTION_TYPE_AUTH,
    .process = &proc,
  };
  [mockES triggerHandler:&m];

  XCTAssertEqual([events count], 1);
  XCTAssertEqual(events[0].result, ES_AUTH_RESULT_ALLOW);
  XCTAssertEqual(events[0].shouldCache, false);
}

- (void)tearDown {
  [super tearDown];
}

@end
