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

NSString *testBinariesPath = @"santa/Source/santad/testdata/binaryrules";

@interface SNTApplicationTest : XCTestCase
@property id mockSNTDatabaseController;
@end

@implementation SNTApplicationTest
- (void)setUp {
  [super setUp];
  fclose(stdout);
  self.mockSNTDatabaseController = OCMClassMock([SNTDatabaseController class]);
}

- (void)tearDown {
  [self.mockSNTDatabaseController stopMocking];
  [super tearDown];
}

- (BOOL)checkBinaryExecution:(NSString *)binaryName
                  wantResult:(es_auth_result_t)wantResult
                  clientMode:(NSInteger)clientMode {
  MockEndpointSecurity *mockES = [MockEndpointSecurity mockEndpointSecurity];
  [mockES reset];

  id mockConfigurator = OCMClassMock([SNTConfigurator class]);

  OCMStub([mockConfigurator configurator]).andReturn(mockConfigurator);
  // Ensure that static rules do not interfere.
  OCMStub([mockConfigurator staticRules]).andReturn(nil);
  // Ensure the mode is set.
  OCMStub([mockConfigurator clientMode]).andReturn(clientMode);
  OCMStub([mockConfigurator failClosed]).andReturn(NO);

  NSString *baseTestPath = @"santa/Source/santad/testdata/binaryrules";
  NSString *testPath = [NSString pathWithComponents:@[
    [[[NSProcessInfo processInfo] environment] objectForKey:@"TEST_SRCDIR"], baseTestPath
  ]];

  OCMStub([self.mockSNTDatabaseController databasePath]).andReturn(testPath);

  SNTApplication *app = [[SNTApplication alloc] init];
  [app start];

  XCTestExpectation *santaInit =
    [self expectationWithDescription:@"Wait for Santa to subscribe to EndpointSecurity"];

  dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
    while ([mockES.subscriptions[ES_EVENT_TYPE_AUTH_EXEC] isEqualTo:@NO])
      ;
    [santaInit fulfill];
  });

  // Ugly hack to deflake the test and allow listenForDecisionRequests to install the correct
  // decision callback.
  sleep(1);
  [self waitForExpectations:@[ santaInit ] timeout:10.0];

  XCTestExpectation *expectation =
    [self expectationWithDescription:@"Wait for santa's Auth dispatch queue"];
  __block ESResponse *got = nil;
  [mockES registerResponseCallback:ES_EVENT_TYPE_AUTH_EXEC
                      withCallback:^(ESResponse *r) {
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

  [self waitForExpectations:@[ expectation ] timeout:10.0];
  NSString *clientModeStr = (clientMode == SNTClientModeLockdown) ? @"LOCKDOWN" : @"MONITOR";

  XCTAssertEqual(got.result, wantResult,
                 @"received unexpected ES response on executing \"%@/%@\" in clientMode %@",
                 testPath, binaryName, clientModeStr);
}

/**
 * testRules ensures that we get the expected outcome when the mocks "execute"
 * our test binaries.
 **/

- (void)testBinaryWithSHA256BlockRuleIsBlockedInLockdownMode {
  [self checkBinaryExecution:@"badbinary"
                  wantResult:ES_AUTH_RESULT_DENY
                  clientMode:SNTClientModeLockdown];
}

- (void)testBinaryWithSHA256BlockRuleIsBlockedInMonitorMode {
  [self checkBinaryExecution:@"badbinary"
                  wantResult:ES_AUTH_RESULT_DENY
                  clientMode:SNTClientModeMonitor];
}

- (void)testBinaryWithSHA256AllowRuleIsNotBlockedInLockdownMode {
  [self checkBinaryExecution:@"goodbinary"
                  wantResult:ES_AUTH_RESULT_ALLOW
                  clientMode:SNTClientModeLockdown];
}

- (void)testBinaryWithSHA256AllowRuleIsNotBlockedInMonitorMode {
  [self checkBinaryExecution:@"goodbinary"
                  wantResult:ES_AUTH_RESULT_ALLOW
                  clientMode:SNTClientModeMonitor];
}

- (void)testBinaryWithCertificateAllowRuleIsNotBlockedInLockdownMode {
  [self checkBinaryExecution:@"goodcert"
                  wantResult:ES_AUTH_RESULT_ALLOW
                  clientMode:SNTClientModeLockdown];
}

- (void)testBinaryWithCertificateAllowRuleIsNotBlockedInMonitorMode {
  [self checkBinaryExecution:@"goodcert"
                  wantResult:ES_AUTH_RESULT_ALLOW
                  clientMode:SNTClientModeMonitor];
}

- (void)testBinaryWithCertificateBlockRuleIsBlockedInLockdownMode {
  [self checkBinaryExecution:@"badcert"
                  wantResult:ES_AUTH_RESULT_DENY
                  clientMode:SNTClientModeLockdown];
}

- (void)testBinaryWithCertificateBlockRuleIsNotBlockedInMonitorMode {
  [self checkBinaryExecution:@"badcert"
                  wantResult:ES_AUTH_RESULT_DENY
                  clientMode:SNTClientModeMonitor];
}

- (void)testBinaryWithTeamIDBlockRuleIsBlockedInLockdownMode {
  [self checkBinaryExecution:@"banned_teamid"
                  wantResult:ES_AUTH_RESULT_DENY
                  clientMode:SNTClientModeLockdown];
}

- (void)testBinaryWithTeamIDBlockRuleIsBlockedInMonitorMode {
  [self checkBinaryExecution:@"banned_teamid"
                  wantResult:ES_AUTH_RESULT_DENY
                  clientMode:SNTClientModeMonitor];
}

- (void)testBinaryWithSHA256AllowRuleAndBlockedTeamIDRuleIsAllowedInLockdownMode {
  [self checkBinaryExecution:@"banned_teamid_allowed_binary"
                  wantResult:ES_AUTH_RESULT_ALLOW
                  clientMode:SNTClientModeLockdown];
}

- (void)testBinaryWithSHA256AllowRuleAndBlockedTeamIDRuleIsAllowedInMonitorMode {
  [self checkBinaryExecution:@"banned_teamid_allowed_binary"
                  wantResult:ES_AUTH_RESULT_ALLOW
                  clientMode:SNTClientModeMonitor];
}

- (void)testBinaryWithoutBlockOrAllowRuleIsAllowedInLockdownMode {
  [self checkBinaryExecution:@"noop"
                  wantResult:ES_AUTH_RESULT_DENY
                  clientMode:SNTClientModeLockdown];
}

- (void)testBinaryWithoutBlockOrAllowRuleIsAllowedInMonitorMode {
  [self checkBinaryExecution:@"noop"
                  wantResult:ES_AUTH_RESULT_ALLOW
                  clientMode:SNTClientModeMonitor];
}

@end
