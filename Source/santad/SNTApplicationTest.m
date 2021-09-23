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
#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/santad/SNTApplication.h"
#import "Source/santad/SNTDatabaseController.h"

#include "Source/santad/EventProviders/EndpointSecurityTestUtil.h"

@interface SNTApplicationTest : XCTestCase
@property id mockSNTDatabaseController;
@end

@implementation SNTApplicationTest
- (void)setUp {
  [super setUp];
  fclose(stdout);
  self.mockSNTDatabaseController = OCMClassMock([SNTDatabaseController class]);
  XCTAssertTrue([[SNTConfigurator configurator] enableSystemExtension]);
}

- (void)tearDown {
  [self.mockSNTDatabaseController stopMocking];
  [super tearDown];
}

- (void)checkBinaryExecution:(NSString *)binaryName
                    testPath:(NSString *)testPath
                  wantResult:(es_auth_result_t)wantResult {
  MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
  [mockES reset];

  OCMStub([self.mockSNTDatabaseController databasePath]).andReturn(testPath);

  SNTApplication *app = [[SNTApplication alloc] init];
  [app start];

  // es events will start flowing in as soon as es_subscribe is called, regardless
  // of whether we're ready or not for it.
  XCTestExpectation *santaInit =
    [self expectationWithDescription:@"Wait for Santa to subscribe to EndpointSecurity"];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
    while (!mockES.subscribed)
      ;
    [santaInit fulfill];
  });

  [self waitForExpectations:@[ santaInit ] timeout:60.0];

  XCTestExpectation *expectation =
    [self expectationWithDescription:@"Wait for santa's Auth dispatch queue"];
  __block ESResponse *got = nil;
  [mockES registerResponseCallback:^(ESResponse *r) {
    got = r;
    [expectation fulfill];
  }];

  NSString *binaryPath = [NSString pathWithComponents:@[ testPath, binaryName ]];
  struct stat fileStat;
  lstat(binaryPath.UTF8String, &fileStat);
  ESMessage *msg = [[ESMessage alloc] initWithBlock:^(ESMessage *m) {
    m.binaryPath = binaryPath;
    m.executable->stat = fileStat;
    m.message->action_type = ES_ACTION_TYPE_AUTH;
    m.message->event_type = ES_EVENT_TYPE_AUTH_EXEC;
    m.message->event = (es_events_t){.exec = {.target = m.process}};
  }];

  [mockES triggerHandler:msg.message];

  [self waitForExpectations:@[ expectation ] timeout:60.0];

  XCTAssertEqual(got.result, wantResult, @"received unexpected ES response on executing \"%@/%@\"",
                 testPath, binaryName);
}

- (void)testBinaryRules {
  NSString *testPath = @"santa/Source/santad/testdata/binaryrules";
  NSDictionary *testCases = @{
    @"badbinary" : [NSNumber numberWithInt:ES_AUTH_RESULT_DENY],
    @"goodbinary" : [NSNumber numberWithInt:ES_AUTH_RESULT_ALLOW],
    @"noop" : [NSNumber numberWithInt:ES_AUTH_RESULT_ALLOW],

  };
  NSString *fullTestPath = [NSString pathWithComponents:@[
    [[[NSProcessInfo processInfo] environment] objectForKey:@"TEST_SRCDIR"], testPath
  ]];

  for (NSString *binary in testCases) {
    [self checkBinaryExecution:binary
                      testPath:fullTestPath
                    wantResult:[testCases[binary] intValue]];
  }
}

- (void)testCertRules {
  NSString *testPath = @"santa/Source/santad/testdata/binaryrules";
  NSDictionary *testCases = @{
    @"badcert" : [NSNumber numberWithInt:ES_AUTH_RESULT_DENY],
    @"goodcert" : [NSNumber numberWithInt:ES_AUTH_RESULT_ALLOW],
    @"noop" : [NSNumber numberWithInt:ES_AUTH_RESULT_ALLOW],
  };
  NSString *fullTestPath = [NSString pathWithComponents:@[
    [[[NSProcessInfo processInfo] environment] objectForKey:@"TEST_SRCDIR"], testPath
  ]];

  for (NSString *binary in testCases) {
    [self checkBinaryExecution:binary
                      testPath:fullTestPath
                    wantResult:[testCases[binary] intValue]];
  }
}

@end
