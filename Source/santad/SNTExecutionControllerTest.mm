/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#include <EndpointSecurity/ESTypes.h>
#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <dispatch/dispatch.h>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#include "Source/common/TestUtils.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#import "Source/santad/SNTDecisionCache.h"
#import "Source/santad/SNTExecutionController.h"

using santa::santad::event_providers::endpoint_security::Message;

using PostActionBlock = bool (^)(SNTAction);
using VerifyPostActionBlock = PostActionBlock (^)(SNTAction);

static const char *kExampleSigningID = "example.signing.id";
static const char *kExampleTeamID = "myteamid";

VerifyPostActionBlock verifyPostAction = ^PostActionBlock(SNTAction wantAction) {
  return ^bool(SNTAction gotAction) {
    XCTAssertEqual(gotAction, wantAction);
    return true;
  };
};

@interface SNTExecutionControllerTest : XCTestCase
@property id mockDecisionCache;
@property id mockConfigurator;
@property id mockCodesignChecker;
@property id mockFileInfo;
@property id mockRuleDatabase;
@property id mockEventDatabase;

@property SNTExecutionController *sut;
@end

@implementation SNTExecutionControllerTest

- (void)setUp {
  [super setUp];

  self.mockDecisionCache = OCMStrictClassMock([SNTDecisionCache class]);
  OCMStub([self.mockDecisionCache sharedCache]).andReturn(self.mockDecisionCache);
  OCMStub([self.mockDecisionCache cacheDecision:OCMOCK_ANY]);

  [[SNTMetricSet sharedInstance] reset];

  self.mockCodesignChecker = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([self.mockCodesignChecker alloc]).andReturn(self.mockCodesignChecker);
  OCMStub([self.mockCodesignChecker initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:NULL]])
    .andReturn(self.mockCodesignChecker);

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  NSURL *url = [NSURL URLWithString:@"https://localhost/test"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(url);

  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([self.mockFileInfo alloc]).andReturn(self.mockFileInfo);
  OCMStub([self.mockFileInfo initWithEndpointSecurityFile:NULL error:[OCMArg setTo:nil]])
    .ignoringNonObjectArgs()
    .andReturn(self.mockFileInfo);
  OCMStub([self.mockFileInfo codesignCheckerWithError:[OCMArg setTo:nil]])
    .andReturn(self.mockCodesignChecker);

  self.mockRuleDatabase = OCMClassMock([SNTRuleTable class]);
  self.mockEventDatabase = OCMClassMock([SNTEventTable class]);

  self.sut = [[SNTExecutionController alloc] initWithRuleTable:self.mockRuleDatabase
                                                    eventTable:self.mockEventDatabase
                                                 notifierQueue:nil
                                                    syncdQueue:nil
                                                     ttyWriter:nullptr
                                      entitlementsPrefixFilter:nil
                                      entitlementsTeamIDFilter:nil];
}

- (void)tearDown {
  // Make sure `self.sut` is deallocated before the mocks are deallocated and
  // call into `stopMocking`.
  self.sut = nil;
}

- (void)checkMetricCounters:(const NSString *)expectedFieldValueName
                   expected:(NSNumber *)expectedValue {
  SNTMetricSet *metricSet = [SNTMetricSet sharedInstance];
  NSDictionary *eventCounter = [metricSet export][@"metrics"][@"/santa/events"];
  BOOL foundField;
  for (NSDictionary *fieldValue in eventCounter[@"fields"][@"action_response"]) {
    if (![expectedFieldValueName isEqualToString:fieldValue[@"value"]]) continue;
    XCTAssertEqualObjects(expectedValue, fieldValue[@"data"],
                          @"%@ counter does not match expected value", expectedFieldValueName);
    foundField = YES;
    break;
  }

  if (!foundField && expectedValue.intValue != 0) {
    XCTFail(@"failed to find %@ field value", expectedFieldValueName);
  }
}

- (void)testSynchronousShouldProcessExecEvent {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t fileExec = MakeESFile("bar", {
                                           .st_dev = 12,
                                           .st_ino = 34,
                                         });
  es_process_t procExec = MakeESProcess(&fileExec);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc);
  esMsg.event.exec.target = &procExec;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  // Undo the default mocks
  self.mockDecisionCache = OCMStrictClassMock([SNTDecisionCache class]);
  OCMStub([self.mockDecisionCache sharedCache]).andReturn(self.mockDecisionCache);

  // Throw on non-AUTH EXEC events
  {
    esMsg.event_type = ES_EVENT_TYPE_NOTIFY_EXEC;
    Message msg(mockESApi, &esMsg);
    XCTAssertThrows([self.sut synchronousShouldProcessExecEvent:msg]);
  }

  // "Normal" events should be processed
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_EXEC;
    Message msg(mockESApi, &esMsg);
    XCTAssertTrue([self.sut synchronousShouldProcessExecEvent:msg]);
  }

  // Long or truncated paths are not handled
  {
    size_t oldLen = esMsg.event.exec.target->executable->path.length;
    esMsg.event.exec.target->executable->path.length = 24000;
    es_file_t *targetExecutable = esMsg.event.exec.target->executable;

    Message msg(mockESApi, &esMsg);

    OCMExpect(
      [self.mockDecisionCache cacheDecision:[OCMArg checkWithBlock:^BOOL(SNTCachedDecision *cd) {
                                return cd.decision == SNTEventStateBlockLongPath &&
                                       cd.vnodeId.fsid == targetExecutable->stat.st_dev &&
                                       cd.vnodeId.fileid == targetExecutable->stat.st_ino;
                              }]]);

    XCTAssertFalse([self.sut synchronousShouldProcessExecEvent:msg]);

    esMsg.event.exec.target->executable->path.length = oldLen;
    esMsg.event.exec.target->executable->path_truncated = true;

    OCMExpect(
      [self.mockDecisionCache cacheDecision:[OCMArg checkWithBlock:^BOOL(SNTCachedDecision *cd) {
                                return cd.decision == SNTEventStateBlockLongPath &&
                                       cd.vnodeId.fsid == targetExecutable->stat.st_dev &&
                                       cd.vnodeId.fileid == targetExecutable->stat.st_ino;
                              }]]);

    XCTAssertFalse([self.sut synchronousShouldProcessExecEvent:msg]);

    XCTAssertTrue(OCMVerifyAll(self.mockDecisionCache));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)validateExecEvent:(SNTAction)wantAction
             messageSetup:(void (^)(es_message_t *))messageSetupBlock {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t fileExec = MakeESFile("bar", {
                                           .st_dev = 12,
                                           .st_ino = 34,
                                         });
  es_process_t procExec = MakeESProcess(&fileExec);
  procExec.is_platform_binary = false;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc);
  esMsg.event.exec.target = &procExec;

  if (messageSetupBlock) {
    messageSetupBlock(&esMsg);
  }

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  {
    Message msg(mockESApi, &esMsg);
    [self.sut validateExecEvent:msg postAction:verifyPostAction(wantAction)];
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)validateExecEvent:(SNTAction)wantAction {
  [self validateExecEvent:wantAction messageSetup:nil];
}

- (void)stubRule:(SNTRule *)rule forIdentifiers:(struct RuleIdentifiers)wantIdentifiers {
  SNTRule *myRule = [[SNTRule alloc] init];
  myRule.state = rule.state;
  myRule.type = rule.type;
  OCMStub([self.mockRuleDatabase ruleForIdentifiers:wantIdentifiers])
    .ignoringNonObjectArgs()
    .andDo(^(NSInvocation *inv) {
      struct RuleIdentifiers gotIdentifiers = {};
      [inv getArgument:&gotIdentifiers atIndex:2];

      XCTAssertEqualObjects(gotIdentifiers.binarySHA256, wantIdentifiers.binarySHA256);
      XCTAssertEqualObjects(gotIdentifiers.signingID, wantIdentifiers.signingID);
      XCTAssertEqualObjects(gotIdentifiers.certificateSHA256, wantIdentifiers.certificateSHA256);
      XCTAssertEqualObjects(gotIdentifiers.teamID, wantIdentifiers.teamID);
    })
    .andReturn(rule);
}

- (void)testBinaryAllowRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowBinary expected:@1];
}

- (void)testBinaryBlockRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateBlock;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondDeny];
  [self checkMetricCounters:kBlockBinary expected:@1];
}

- (void)testSigningIDAllowRule {
  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeSigningID;

  NSString *signingID = [NSString stringWithFormat:@"%s:%s", kExampleTeamID, kExampleSigningID];

  [self stubRule:rule forIdentifiers:{ .signingID = signingID, .teamID = @(kExampleTeamID) }];

  [self validateExecEvent:SNTActionRespondAllow
             messageSetup:^(es_message_t *msg) {
               msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
               msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
             }];

  [self checkMetricCounters:kAllowSigningID expected:@1];
}

- (void)testSigningIDBlockRule {
  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateBlock;
  rule.type = SNTRuleTypeSigningID;

  NSString *signingID = [NSString stringWithFormat:@"%s:%s", kExampleTeamID, kExampleSigningID];
  [self stubRule:rule forIdentifiers:{ .signingID = signingID, .teamID = @(kExampleTeamID) }];

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t *msg) {
               msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
               msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
             }];
  [self checkMetricCounters:kBlockSigningID expected:@1];
}

- (void)testTeamIDAllowRule {
  OCMStub([self.mockCodesignChecker signingInformation]).andReturn((@{
    (__bridge NSString *)kSecCodeInfoTeamIdentifier : @(kExampleTeamID),
  }));

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeTeamID;

  [self stubRule:rule forIdentifiers:{ .teamID = @(kExampleTeamID) }];

  [self validateExecEvent:SNTActionRespondAllow
             messageSetup:^(es_message_t *msg) {
               msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
             }];
  [self checkMetricCounters:kAllowTeamID expected:@1];
}

- (void)testTeamIDBlockRule {
  OCMStub([self.mockCodesignChecker signingInformation]).andReturn((@{
    (__bridge NSString *)kSecCodeInfoTeamIdentifier : @(kExampleTeamID),
  }));

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateBlock;
  rule.type = SNTRuleTypeTeamID;

  [self stubRule:rule forIdentifiers:{ .teamID = @(kExampleTeamID) }];

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t *msg) {
               msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
             }];
  [self checkMetricCounters:kBlockTeamID expected:@1];
}

- (void)testCertificateAllowRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);

  id cert = OCMClassMock([MOLCertificate class]);
  OCMStub([self.mockCodesignChecker leafCertificate]).andReturn(cert);
  OCMStub([cert SHA256]).andReturn(@"a");

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeCertificate;

  [self stubRule:rule forIdentifiers:{.certificateSHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowCertificate expected:@1];
}

- (void)testCertificateBlockRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);

  id cert = OCMClassMock([MOLCertificate class]);
  OCMStub([self.mockCodesignChecker leafCertificate]).andReturn(cert);
  OCMStub([cert SHA256]).andReturn(@"a");

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateBlock;
  rule.type = SNTRuleTypeCertificate;

  [self stubRule:rule forIdentifiers:{.certificateSHA256 = @"a"}];

  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self validateExecEvent:SNTActionRespondDeny];

  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kBlockCertificate expected:@1];
}

- (void)testBinaryAllowCompilerRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllowCompiler];
  [self checkMetricCounters:kAllowCompiler expected:@1];
}

- (void)testBinaryAllowCompilerRuleDisabled {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(NO);

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowBinary expected:@1];
}

- (void)testBinaryAllowTransitiveRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowTransitive;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowTransitive expected:@1];
}

- (void)testBinaryAllowTransitiveRuleDisabled {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(NO);

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowTransitive;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self validateExecEvent:SNTActionRespondDeny];

  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kAllowBinary expected:@0];
  [self checkMetricCounters:kAllowTransitive expected:@0];
}

- (void)testSigningIDAllowCompilerRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  NSString *signingID = [NSString stringWithFormat:@"%s:%s", kExampleTeamID, kExampleSigningID];

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeSigningID;

  [self stubRule:rule
    forIdentifiers:{ .binarySHA256 = @"a", .signingID = signingID, .teamID = @(kExampleTeamID) }];

  [self validateExecEvent:SNTActionRespondAllowCompiler
             messageSetup:^(es_message_t *msg) {
               msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
               msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
             }];

  [self checkMetricCounters:kAllowCompiler expected:@1];
}

- (void)testSigningIDAllowTransitiveRuleDisabled {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(NO);

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowTransitive;
  rule.type = SNTRuleTypeSigningID;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self validateExecEvent:SNTActionRespondDeny];

  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kAllowSigningID expected:@0];
  [self checkMetricCounters:kAllowTransitive expected:@0];
}

- (void)testThatPlatformBinaryCachedDecisionsSetModeCorrectly {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(NO);

  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.decision = SNTEventStateAllowBinary;
  OCMStub([self.mockRuleDatabase criticalSystemBinaries]).andReturn(@{@"a" : cd});

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowBinary expected:@1];
  [self checkMetricCounters:kAllowUnknown expected:@0];

  XCTAssertEqual(cd.decisionClientMode, SNTClientModeLockdown);
}

- (void)testDefaultDecision {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  OCMExpect([self.mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self validateExecEvent:SNTActionRespondAllow];

  OCMExpect([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);

  [self validateExecEvent:SNTActionRespondDeny];

  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kBlockUnknown expected:@1];
  [self checkMetricCounters:kAllowUnknown expected:@1];
}

- (void)testUnreadableFailOpen {
  // Undo the default mocks
  [self.mockFileInfo stopMocking];
  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);

  OCMStub([self.mockFileInfo alloc]).andReturn(nil);
  OCMStub([self.mockFileInfo initWithPath:OCMOCK_ANY error:[OCMArg setTo:nil]]).andReturn(nil);

  OCMStub([self.mockConfigurator failClosed]).andReturn(NO);

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowNoFileInfo expected:@1];
}

- (void)testUnreadableFailClosed {
  // Undo the default mocks
  [self.mockFileInfo stopMocking];
  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);

  OCMStub([self.mockFileInfo alloc]).andReturn(nil);
  OCMStub([self.mockFileInfo initWithPath:OCMOCK_ANY error:[OCMArg setTo:nil]]).andReturn(nil);

  OCMStub([self.mockConfigurator failClosed]).andReturn(YES);

  [self validateExecEvent:SNTActionRespondDeny];
  [self checkMetricCounters:kDenyNoFileInfo expected:@1];
}

- (void)testMissingShasum {
  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowScope expected:@1];
}

- (void)testOutOfScope {
  OCMStub([self.mockFileInfo isMachO]).andReturn(NO);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowScope expected:@1];
}

- (void)testPageZero {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo isMissingPageZero]).andReturn(YES);
  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self validateExecEvent:SNTActionRespondDeny];
  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kBlockUnknown expected:@1];
}

- (void)testAllEventUpload {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  OCMExpect([self.mockConfigurator enableAllEventUpload]).andReturn(YES);
  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllow];
  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
}

- (void)testDisableUnknownEventUpload {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  OCMExpect([self.mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  OCMExpect([self.mockConfigurator enableAllEventUpload]).andReturn(NO);
  OCMExpect([self.mockConfigurator disableUnknownEventUpload]).andReturn(YES);

  [self validateExecEvent:SNTActionRespondAllow];
  OCMVerify(never(), [self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);
  [self checkMetricCounters:kAllowUnknown expected:@1];
}

@end
