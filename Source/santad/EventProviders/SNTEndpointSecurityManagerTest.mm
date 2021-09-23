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
const NSString *const kBenignPath = @"/some/other/path";

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
  (void)snt;  // Make it appear used for the sake of -Wunused-variable

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

  __block es_file_t dbFile = {.path = MakeStringToken(kEventsDBPath)};
  ESMessage *m = [[ESMessage alloc] initWithBlock:^(ESMessage *m) {
    m.binaryPath = @"somebinary";
    m.message->action_type = ES_ACTION_TYPE_AUTH;
    m.message->event_type = ES_EVENT_TYPE_AUTH_UNLINK;
    m.message->event = (es_events_t){.unlink = {.target = &dbFile}};
    m.message->mach_time = 1234;
    m.message->deadline = 1234;
  }];

  [mockES triggerHandler:m.message];

  [self waitForExpectations:@[ expectation ] timeout:60.0];

  for (ESResponse *resp in events) {
    XCTAssertEqual(
      resp.result, ES_AUTH_RESULT_DENY,
      @"Failed to automatically deny on timeout and also the malicious event afterwards");
  }
}

- (void)testDeleteRulesDB {
  NSDictionary<const NSString *, NSNumber *> *testCases = @{
    kEventsDBPath : [NSNumber numberWithInt:ES_AUTH_RESULT_DENY],
    kRulesDBPath : [NSNumber numberWithInt:ES_AUTH_RESULT_DENY],
    kBenignPath : [NSNumber numberWithInt:ES_AUTH_RESULT_ALLOW],
  };
  for (const NSString *testPath in testCases) {
    MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
    [mockES reset];
    SNTEndpointSecurityManager *snt = [[SNTEndpointSecurityManager alloc] init];
    (void)snt;  // Make it appear used for the sake of -Wunused-variable

    XCTestExpectation *expectation = [self expectationWithDescription:@"Wait for response from ES"];
    __block ESResponse *got;
    [mockES registerResponseCallback:^(ESResponse *r) {
      got = r;
      [expectation fulfill];
    }];

    __block es_file_t dbFile = {.path = MakeStringToken(testPath)};
    ESMessage *m = [[ESMessage alloc] initWithBlock:^(ESMessage *m) {
      m.binaryPath = @"somebinary";
      m.message->action_type = ES_ACTION_TYPE_AUTH;
      m.message->event_type = ES_EVENT_TYPE_AUTH_UNLINK;
      m.message->event = (es_events_t){.unlink = {.target = &dbFile}};
    }];

    [mockES triggerHandler:m.message];

    [self waitForExpectations:@[ expectation ] timeout:60.0];

    XCTAssertEqual(got.result, [testCases objectForKey:testPath].intValue,
                   @"Incorrect handling of delete of %@", testPath);
    XCTAssertTrue(got.shouldCache, @"Failed to cache deletion decision of %@", testPath);
  }
}

- (void)testSkipOtherESEvents {
  MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
  [mockES reset];
  SNTEndpointSecurityManager *snt = [[SNTEndpointSecurityManager alloc] init];
  (void)snt;  // Make it appear used for the sake of -Wunused-variable

  XCTestExpectation *expectation = [self expectationWithDescription:@"Wait for response from ES"];
  __block ESResponse *got;
  [mockES registerResponseCallback:^(ESResponse *r) {
    got = r;
    [expectation fulfill];
  }];

  __block es_file_t dbFile = {.path = MakeStringToken(@"/some/other/path")};
  ESMessage *m = [[ESMessage alloc] initWithBlock:^(ESMessage *m) {
    m.process->is_es_client = true;
    m.binaryPath = @"somebinary";
    m.message->action_type = ES_ACTION_TYPE_AUTH;
    m.message->event_type = ES_EVENT_TYPE_AUTH_UNLINK;
    m.message->event = (es_events_t){.unlink = {.target = &dbFile}};
  }];

  [mockES triggerHandler:m.message];

  [self waitForExpectations:@[ expectation ] timeout:60.0];

  XCTAssertEqual(got.result, ES_AUTH_RESULT_ALLOW);
}

- (void)testRenameOverwriteRulesDB {
  NSDictionary<const NSString *, NSNumber *> *testCases = @{
    kEventsDBPath : [NSNumber numberWithInt:ES_AUTH_RESULT_DENY],
    kRulesDBPath : [NSNumber numberWithInt:ES_AUTH_RESULT_DENY],
    kBenignPath : [NSNumber numberWithInt:ES_AUTH_RESULT_ALLOW],
  };
  for (const NSString *testPath in testCases) {
    MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
    [mockES reset];
    SNTEndpointSecurityManager *snt = [[SNTEndpointSecurityManager alloc] init];
    (void)snt;  // Make it appear used for the sake of -Wunused-variable

    XCTestExpectation *expectation = [self expectationWithDescription:@"Wait for response from ES"];
    __block ESResponse *got;
    [mockES registerResponseCallback:^(ESResponse *r) {
      got = r;
      [expectation fulfill];
    }];

    __block es_file_t otherFile = {.path = MakeStringToken(@"/some/other/path")};
    __block es_file_t dbFile = {.path = MakeStringToken(testPath)};
    ESMessage *m = [[ESMessage alloc] initWithBlock:^(ESMessage *m) {
      m.binaryPath = @"somebinary";
      m.message->action_type = ES_ACTION_TYPE_AUTH;
      m.message->event_type = ES_EVENT_TYPE_AUTH_RENAME;
      m.message->event = (es_events_t){
        .rename =
          {
            .source = &otherFile,
            .destination_type = ES_DESTINATION_TYPE_EXISTING_FILE,
            .destination = {.existing_file = &dbFile},
          },
      };
    }];

    [mockES triggerHandler:m.message];

    [self waitForExpectations:@[ expectation ] timeout:60.0];

    XCTAssertEqual(got.result, [testCases objectForKey:testPath].intValue,
                   @"Incorrect handling of rename of %@", testPath);
    XCTAssertTrue(got.shouldCache, @"Failed to cache rename auth decision of %@", testPath);
  }
}

- (void)testRenameRulesDB {
  NSDictionary<const NSString *, NSNumber *> *testCases = @{
    kEventsDBPath : [NSNumber numberWithInt:ES_AUTH_RESULT_DENY],
    kRulesDBPath : [NSNumber numberWithInt:ES_AUTH_RESULT_DENY],
    kBenignPath : [NSNumber numberWithInt:ES_AUTH_RESULT_ALLOW],
  };

  for (const NSString *testPath in testCases) {
    MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
    [mockES reset];
    SNTEndpointSecurityManager *snt = [[SNTEndpointSecurityManager alloc] init];
    (void)snt;  // Make it appear used for the sake of -Wunused-variable

    XCTestExpectation *expectation = [self expectationWithDescription:@"Wait for response from ES"];
    __block ESResponse *got;
    [mockES registerResponseCallback:^(ESResponse *r) {
      got = r;
      [expectation fulfill];
    }];

    __block es_file_t otherFile = {.path = MakeStringToken(@"/some/other/path")};
    __block es_file_t dbFile = {.path = MakeStringToken(testPath)};
    ESMessage *m = [[ESMessage alloc] initWithBlock:^(ESMessage *m) {
      m.binaryPath = @"somebinary";
      m.message->action_type = ES_ACTION_TYPE_AUTH;
      m.message->event_type = ES_EVENT_TYPE_AUTH_RENAME;
      m.message->event = (es_events_t){
        .rename =
          {
            .source = &dbFile,
            .destination_type = ES_DESTINATION_TYPE_NEW_PATH,
            .destination = {.new_path =
                              {
                                .dir = &otherFile,
                                .filename = MakeStringToken(@"someotherfilename"),
                              }},
          },
      };
    }];

    [mockES triggerHandler:m.message];

    [self waitForExpectations:@[ expectation ] timeout:60.0];

    XCTAssertEqual(got.result, [testCases objectForKey:testPath].intValue,
                   @"Incorrect handling of rename of %@", testPath);

    XCTAssertTrue(got.shouldCache, @"Failed to cache rename auth decision of %@", testPath);
  }
}

@end
