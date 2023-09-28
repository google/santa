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

#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#import <dispatch/dispatch.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"
#import "Source/santad/Metrics.h"
#import "Source/santad/SNTDatabaseController.h"
#import "Source/santad/SNTDecisionCache.h"
#include "Source/santad/SantadDeps.h"

using santa::santad::SantadDeps;
using santa::santad::event_providers::endpoint_security::Message;

NSString *testBinariesPath = @"santa/Source/santad/testdata/binaryrules";
static const char *kAllowedSigningID = "com.google.allowed_signing_id";
static const char *kBlockedSigningID = "com.google.blocked_signing_id";
static const char *kNoRuleMatchSigningID = "com.google.no_rule_match_signing_id";
static const char *kBlockedTeamID = "EQHXZ8M8AV";
static const char *kAllowedTeamID = "TJNVEKW352";

@interface SantadTest : XCTestCase
@property id mockSNTDatabaseController;
@end

@implementation SantadTest
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
                  clientMode:(NSInteger)clientMode
                 cdValidator:(BOOL (^)(SNTCachedDecision *))cdValidator
                messageSetup:(void (^)(es_message_t *))messageSetupBlock {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();

  id mockDecisionCache = OCMClassMock([SNTDecisionCache class]);
  OCMStub([mockDecisionCache sharedCache]).andReturn(mockDecisionCache);
  if (cdValidator) {
    OCMExpect([mockDecisionCache cacheDecision:[OCMArg checkWithBlock:cdValidator]]);
  }

  id mockConfigurator = OCMClassMock([SNTConfigurator class]);

  OCMStub([mockConfigurator configurator]).andReturn(mockConfigurator);
  // Ensure that static rules do not interfere.
  OCMStub([mockConfigurator staticRules]).andReturn(nil);
  // Ensure the mode is set.
  OCMStub([mockConfigurator clientMode]).andReturn(clientMode);
  OCMStub([mockConfigurator failClosed]).andReturn(NO);
  OCMStub([mockConfigurator fileAccessPolicyUpdateIntervalSec]).andReturn(600);

  NSString *baseTestPath = @"santa/Source/santad/testdata/binaryrules";
  NSString *testPath = [NSString pathWithComponents:@[
    [[[NSProcessInfo processInfo] environment] objectForKey:@"TEST_SRCDIR"], baseTestPath
  ]];

  OCMStub([self.mockSNTDatabaseController databasePath]).andReturn(testPath);

  std::unique_ptr<SantadDeps> deps = SantadDeps::Create(mockConfigurator, nil);

  SNTEndpointSecurityAuthorizer *authClient =
    [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:mockESApi
                                                 metrics:deps->Metrics()
                                          execController:deps->ExecController()
                                      compilerController:deps->CompilerController()
                                         authResultCache:deps->AuthResultCache()];

  XCTestExpectation *expectation =
    [self expectationWithDescription:@"Wait for santa's Auth dispatch queue"];

  EXPECT_CALL(*mockESApi, RespondAuthResult(testing::_, testing::_, wantResult,
                                            wantResult == ES_AUTH_RESULT_ALLOW))
    .WillOnce(testing::InvokeWithoutArgs(^bool {
      [expectation fulfill];
      return true;
    }));

  NSString *binaryPath =
    [[NSString pathWithComponents:@[ testPath, binaryName ]] stringByResolvingSymlinksInPath];
  struct stat fileStat;
  lstat(binaryPath.UTF8String, &fileStat);
  es_file_t file = MakeESFile([binaryPath UTF8String], fileStat);
  es_process_t proc = MakeESProcess(&file);
  proc.is_platform_binary = false;
  // Set a 6.5 second deadline for the message. The base SNTEndpointSecurityClient
  // class leaves a 5 second buffer to auto-respond to messages. A 6 second
  // deadline means there is a 1.5 second leeway given for the processing block
  // to finish its tasks and release the `Message`. This will add about 1 second
  // to the run time of each test case since each one must wait for the
  // deadline block to run and release the message.
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth, 6500);
  esMsg.event.exec.target = &proc;

  if (messageSetupBlock) {
    messageSetupBlock(&esMsg);
  }

  // The test must wait for the ES client async message processing to complete.
  // Otherwise, the `es_message_t` stack variable will go out of scope and will
  // result in undefined behavior in the async dispatch queue block.
  // To do this, track the `Message` retain counts, and only allow the test
  // to continue once the retain count drops to 0 indicating the client is
  // no longer using the message.
  __block int retainCount = 0;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  EXPECT_CALL(*mockESApi, ReleaseMessage).WillRepeatedly(^{
    if (retainCount == 0) {
      XCTFail("Under retain!");
    }
    retainCount--;
    if (retainCount == 0) {
      dispatch_semaphore_signal(sema);
    }
  });
  EXPECT_CALL(*mockESApi, RetainMessage).WillRepeatedly(^{
    retainCount++;
  });

  [authClient handleMessage:Message(mockESApi, &esMsg)
         recordEventMetrics:^(santa::santad::EventDisposition d){
           // This block intentionally left blank
         }];

  [self waitForExpectations:@[ expectation ] timeout:10.0];

  XCTAssertTrue(OCMVerifyAll(mockDecisionCache), "Unable to verify SNTCachedDecision properties");

  XCTAssertEqual(0,
                 dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)),
                 "Failed waiting for message to be processed...");

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (BOOL)checkBinaryExecution:(NSString *)binaryName
                  wantResult:(es_auth_result_t)wantResult
                  clientMode:(NSInteger)clientMode
                 cdValidator:(BOOL (^)(SNTCachedDecision *))cdValidator {
  return [self checkBinaryExecution:binaryName
                         wantResult:wantResult
                         clientMode:clientMode
                        cdValidator:cdValidator
                       messageSetup:nil];
}

/**
 * testRules ensures that we get the expected outcome when the mocks "execute"
 * our test binaries.
 **/

- (void)testBinaryWithSHA256BlockRuleIsBlockedInLockdownMode {
  [self checkBinaryExecution:@"badbinary"
                  wantResult:ES_AUTH_RESULT_DENY
                  clientMode:SNTClientModeLockdown
                 cdValidator:^BOOL(SNTCachedDecision *cd) {
                   return cd.decision == SNTEventStateBlockBinary;
                 }];
}

- (void)testBinaryWithSHA256BlockRuleIsBlockedInMonitorMode {
  [self checkBinaryExecution:@"badbinary"
                  wantResult:ES_AUTH_RESULT_DENY
                  clientMode:SNTClientModeMonitor
                 cdValidator:^BOOL(SNTCachedDecision *cd) {
                   return cd.decision == SNTEventStateBlockBinary;
                 }];
}

- (void)testBinaryWithSHA256AllowRuleIsNotBlockedInLockdownMode {
  [self checkBinaryExecution:@"goodbinary"
                  wantResult:ES_AUTH_RESULT_ALLOW
                  clientMode:SNTClientModeLockdown
                 cdValidator:^BOOL(SNTCachedDecision *cd) {
                   return cd.decision == SNTEventStateAllowBinary;
                 }];
}

- (void)testBinaryWithSHA256AllowRuleIsNotBlockedInMonitorMode {
  [self checkBinaryExecution:@"goodbinary"
                  wantResult:ES_AUTH_RESULT_ALLOW
                  clientMode:SNTClientModeMonitor
                 cdValidator:^BOOL(SNTCachedDecision *cd) {
                   return cd.decision == SNTEventStateAllowBinary;
                 }];
}

- (void)testBinaryWithCertificateAllowRuleIsNotBlockedInLockdownMode {
  [self checkBinaryExecution:@"goodcert"
                  wantResult:ES_AUTH_RESULT_ALLOW
                  clientMode:SNTClientModeLockdown
                 cdValidator:^BOOL(SNTCachedDecision *cd) {
                   return cd.decision == SNTEventStateAllowCertificate;
                 }];
}

- (void)testBinaryWithCertificateAllowRuleIsNotBlockedInMonitorMode {
  [self checkBinaryExecution:@"goodcert"
                  wantResult:ES_AUTH_RESULT_ALLOW
                  clientMode:SNTClientModeMonitor
                 cdValidator:^BOOL(SNTCachedDecision *cd) {
                   return cd.decision == SNTEventStateAllowCertificate;
                 }];
}

- (void)testBinaryWithCertificateBlockRuleIsBlockedInLockdownMode {
  [self checkBinaryExecution:@"badcert"
                  wantResult:ES_AUTH_RESULT_DENY
                  clientMode:SNTClientModeLockdown
                 cdValidator:^BOOL(SNTCachedDecision *cd) {
                   return cd.decision == SNTEventStateBlockCertificate;
                 }];
}

- (void)testBinaryWithCertificateBlockRuleIsBlockedInMonitorMode {
  [self checkBinaryExecution:@"badcert"
                  wantResult:ES_AUTH_RESULT_DENY
                  clientMode:SNTClientModeMonitor
                 cdValidator:^BOOL(SNTCachedDecision *cd) {
                   return cd.decision == SNTEventStateBlockCertificate;
                 }];
}

- (void)testBinaryWithTeamIDAllowRuleAndNoSigningIDMatchIsAllowedInLockdownMode {
  [self checkBinaryExecution:@"allowed_teamid"
    wantResult:ES_AUTH_RESULT_ALLOW
    clientMode:SNTClientModeLockdown
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateAllowTeamID;
    }
    messageSetup:^(es_message_t *msg) {
      msg->event.exec.target->team_id = MakeESStringToken(kAllowedTeamID);
      msg->event.exec.target->signing_id = MakeESStringToken(kNoRuleMatchSigningID);
    }];
}

- (void)testBinaryWithTeamIDAllowRuleAndNoSigningIDMatchIsAllowedInMonitorMode {
  [self checkBinaryExecution:@"allowed_teamid"
    wantResult:ES_AUTH_RESULT_ALLOW
    clientMode:SNTClientModeMonitor
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateAllowTeamID;
    }
    messageSetup:^(es_message_t *msg) {
      msg->event.exec.target->team_id = MakeESStringToken(kAllowedTeamID);
      msg->event.exec.target->signing_id = MakeESStringToken(kNoRuleMatchSigningID);
    }];
}

- (void)testBinaryWithTeamIDBlockRuleAndNoSigningIDMatchIsBlockedInLockdownMode {
  [self checkBinaryExecution:@"banned_teamid"
    wantResult:ES_AUTH_RESULT_DENY
    clientMode:SNTClientModeLockdown
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateBlockTeamID;
    }
    messageSetup:^(es_message_t *msg) {
      msg->event.exec.target->team_id = MakeESStringToken(kBlockedTeamID);
      msg->event.exec.target->signing_id = MakeESStringToken(kNoRuleMatchSigningID);
    }];
}

- (void)testBinaryWithTeamIDBlockRuleAndNoSigningIDMatchIsBlockedInMonitorMode {
  [self checkBinaryExecution:@"banned_teamid"
    wantResult:ES_AUTH_RESULT_DENY
    clientMode:SNTClientModeMonitor
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateBlockTeamID;
    }
    messageSetup:^(es_message_t *msg) {
      msg->event.exec.target->team_id = MakeESStringToken(kBlockedTeamID);
      msg->event.exec.target->signing_id = MakeESStringToken(kNoRuleMatchSigningID);
    }];
}

- (void)testBinaryWithSigningIDBlockRuleIsBlockedInLockdownMode {
  [self checkBinaryExecution:@"banned_signingid"
    wantResult:ES_AUTH_RESULT_DENY
    clientMode:SNTClientModeLockdown
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateBlockSigningID;
    }
    messageSetup:^(es_message_t *msg) {
      msg->event.exec.target->team_id = MakeESStringToken(kBlockedTeamID);
      msg->event.exec.target->signing_id = MakeESStringToken(kBlockedSigningID);
    }];
}

- (void)testBinaryWithSigningIDBlockRuleIsBlockedInMonitorMode {
  [self checkBinaryExecution:@"banned_signingid"
    wantResult:ES_AUTH_RESULT_DENY
    clientMode:SNTClientModeMonitor
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateBlockSigningID;
    }
    messageSetup:^(es_message_t *msg) {
      msg->event.exec.target->team_id = MakeESStringToken(kBlockedTeamID);
      msg->event.exec.target->signing_id = MakeESStringToken(kBlockedSigningID);
    }];
}

- (void)testBinaryWithSigningIDAllowRuleIsAllowedInMonitorMode {
  [self checkBinaryExecution:@"allowed_signingid"
    wantResult:ES_AUTH_RESULT_ALLOW
    clientMode:SNTClientModeMonitor
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateAllowSigningID;
    }
    messageSetup:^(es_message_t *msg) {
      msg->event.exec.target->team_id = MakeESStringToken(kBlockedTeamID);
      msg->event.exec.target->signing_id = MakeESStringToken(kAllowedSigningID);
    }];
}

- (void)testBinaryWithSigningIDAllowRuleIsAllowedInLockdownMode {
  [self checkBinaryExecution:@"allowed_signingid"
    wantResult:ES_AUTH_RESULT_ALLOW
    clientMode:SNTClientModeMonitor
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateAllowSigningID;
    }
    messageSetup:^(es_message_t *msg) {
      msg->event.exec.target->team_id = MakeESStringToken(kBlockedTeamID);
      msg->event.exec.target->signing_id = MakeESStringToken(kAllowedSigningID);
    }];
}

- (void)testBinaryWithSHA256AllowRuleAndBlockedTeamIDRuleIsAllowedInLockdownMode {
  [self checkBinaryExecution:@"banned_teamid_allowed_binary"
    wantResult:ES_AUTH_RESULT_ALLOW
    clientMode:SNTClientModeLockdown
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateAllowBinary;
    }
    messageSetup:^(es_message_t *msg) {
      msg->event.exec.target->team_id = MakeESStringToken(kBlockedTeamID);
      msg->event.exec.target->signing_id = MakeESStringToken(kNoRuleMatchSigningID);
    }];
}

- (void)testBinaryWithSHA256AllowRuleAndBlockedTeamIDRuleIsAllowedInMonitorMode {
  [self checkBinaryExecution:@"banned_teamid_allowed_binary"
    wantResult:ES_AUTH_RESULT_ALLOW
    clientMode:SNTClientModeMonitor
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateAllowBinary;
    }
    messageSetup:^(es_message_t *msg) {
      msg->event.exec.target->team_id = MakeESStringToken(kBlockedTeamID);
      msg->event.exec.target->signing_id = MakeESStringToken(kNoRuleMatchSigningID);
    }];
}

- (void)testBinaryWithoutBlockOrAllowRuleIsBlockedInLockdownMode {
  [self checkBinaryExecution:@"noop"
                  wantResult:ES_AUTH_RESULT_DENY
                  clientMode:SNTClientModeLockdown
                 cdValidator:^BOOL(SNTCachedDecision *cd) {
                   return cd.decision == SNTEventStateBlockUnknown;
                 }];
}

- (void)testBinaryWithoutBlockOrAllowRuleIsAllowedInMonitorMode {
  [self checkBinaryExecution:@"noop"
                  wantResult:ES_AUTH_RESULT_ALLOW
                  clientMode:SNTClientModeMonitor
                 cdValidator:^BOOL(SNTCachedDecision *cd) {
                   return cd.decision == SNTEventStateAllowUnknown;
                 }];
}

@end
