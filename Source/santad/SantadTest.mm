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
#include <string.h>

#include <cctype>
#include <memory>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityClient.h"
#import "Source/santad/Metrics.h"
#import "Source/santad/SNTDatabaseController.h"
#import "Source/santad/SNTDecisionCache.h"
#include "Source/santad/SantadDeps.h"

using santa::Message;
using santa::SantadDeps;

static int HexCharToInt(char hex) {
  if (hex >= '0' && hex <= '9') {
    return hex - '0';
  } else if (hex >= 'A' && hex <= 'F') {
    return hex - 'A' + 10;
  } else if (hex >= 'a' && hex <= 'f') {
    return hex - 'a' + 10;
  } else {
    return -1;
  }
}

static void SetBinaryDataFromHexString(const char *hexStr, uint8_t *buf, size_t bufLen) {
  assert(hexStr != NULL);
  size_t hexStrLen = strlen(hexStr);
  assert(hexStrLen > 0);
  assert(hexStrLen % 2 == 0);
  assert(hexStrLen / 2 == bufLen);

  for (size_t i = 0; i < hexStrLen; i += 2) {
    int upper = HexCharToInt(hexStr[i]);
    int lower = HexCharToInt(hexStr[i + 1]);

    assert(upper != -1);
    assert(lower != -1);

    buf[i / 2] = (uint8_t)(upper << 4) | lower;
  }
}

static const char *kAllowedSigningID = "com.google.allowed_signing_id";
static const char *kBlockedSigningID = "com.google.blocked_signing_id";
static const char *kNoRuleMatchSigningID = "com.google.no_rule_match_signing_id";
static const char *kBlockedTeamID = "EQHXZ8M8AV";
static const char *kAllowedTeamID = "TJNVEKW352";
static const char *kAllowedCDHash = "dedebf2eac732d873008b17b3e44a56599dd614b";
static const char *kBlockedCDHash = "7218eddfee4d3eba4873dedf22d1391d79aea25f";

@interface SNTEndpointSecurityClient (Testing)
@property(nonatomic) double defaultBudget;
@property(nonatomic) int64_t minAllowedHeadroom;
@property(nonatomic) int64_t maxAllowedHeadroom;
@end

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

  NSString *testPath = [NSString pathWithComponents:@[
    [[NSBundle bundleForClass:[self class]] resourcePath],
    @"binaryrules",
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
  XCTAssertEqual(lstat(binaryPath.UTF8String, &fileStat), 0);
  es_file_t file = MakeESFile([binaryPath UTF8String], fileStat);
  es_process_t proc = MakeESProcess(&file);
  proc.is_platform_binary = false;
  proc.codesigning_flags = CS_SIGNED | CS_VALID | CS_HARD | CS_KILL;

  // Set a 6.5 second deadline for the message and clamp deadline headroom to 5
  // seconds. This means there is a 1.5 second leeway given for the processing block
  // to finish its tasks and release the `Message`. This will add about 1 second
  // to the run time of each test case since each one must wait for the
  // deadline block to run and release the message.
  authClient.minAllowedHeadroom = 5 * NSEC_PER_SEC;
  authClient.maxAllowedHeadroom = 5 * NSEC_PER_SEC;
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
         recordEventMetrics:^(santa::EventDisposition d){
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

- (void)testBinaryWithCDHashBlockRuleIsBlockedInLockdownMode {
  [self checkBinaryExecution:@"banned_cdhash"
    wantResult:ES_AUTH_RESULT_DENY
    clientMode:SNTClientModeLockdown
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateBlockCDHash;
    }
    messageSetup:^(es_message_t *msg) {
      SetBinaryDataFromHexString(kBlockedCDHash, msg->event.exec.target->cdhash,
                                 sizeof(msg->event.exec.target->cdhash));
    }];
}

- (void)testBinaryWithCDHashBlockRuleIsBlockedInMonitorMode {
  [self checkBinaryExecution:@"banned_cdhash"
    wantResult:ES_AUTH_RESULT_DENY
    clientMode:SNTClientModeMonitor
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateBlockCDHash;
    }
    messageSetup:^(es_message_t *msg) {
      SetBinaryDataFromHexString(kBlockedCDHash, msg->event.exec.target->cdhash,
                                 sizeof(msg->event.exec.target->cdhash));
    }];
}

- (void)testBinaryWithCDHashAllowRuleIsAllowedInMonitorMode {
  [self checkBinaryExecution:@"allowed_cdhash"
    wantResult:ES_AUTH_RESULT_ALLOW
    clientMode:SNTClientModeMonitor
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateAllowCDHash;
    }
    messageSetup:^(es_message_t *msg) {
      SetBinaryDataFromHexString(kAllowedCDHash, msg->event.exec.target->cdhash,
                                 sizeof(msg->event.exec.target->cdhash));
    }];
}

- (void)testBinaryWithCDHashAllowRuleIsAllowedInLockdownMode {
  [self checkBinaryExecution:@"allowed_cdhash"
    wantResult:ES_AUTH_RESULT_ALLOW
    clientMode:SNTClientModeMonitor
    cdValidator:^BOOL(SNTCachedDecision *cd) {
      return cd.decision == SNTEventStateAllowCDHash;
    }
    messageSetup:^(es_message_t *msg) {
      SetBinaryDataFromHexString(kAllowedCDHash, msg->event.exec.target->cdhash,
                                 sizeof(msg->event.exec.target->cdhash));
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
