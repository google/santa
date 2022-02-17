/// Copyright 2015 Google Inc. All rights reserved.
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

#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/santad/SNTExecutionController.h"

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTRule.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/EventProviders/SNTDriverManager.h"

@interface SNTExecutionControllerTest : XCTestCase
@property id mockConfigurator;
@property id mockCodesignChecker;
@property id mockDriverManager;
@property id mockFileInfo;
@property id mockRuleDatabase;
@property id mockEventDatabase;

@property SNTExecutionController *sut;
@end

@implementation SNTExecutionControllerTest

- (void)setUp {
  [super setUp];

  fclose(stdout);

  self.mockCodesignChecker = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([self.mockCodesignChecker alloc]).andReturn(self.mockCodesignChecker);

  OCMStub([self.mockCodesignChecker initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:NULL]])
    .andReturn(self.mockCodesignChecker);

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  NSURL *url = [NSURL URLWithString:@"https://localhost/test"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(url);

  self.mockDriverManager = OCMClassMock([SNTDriverManager class]);

  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([self.mockFileInfo alloc]).andReturn(self.mockFileInfo);
  OCMStub([self.mockFileInfo initWithPath:OCMOCK_ANY error:[OCMArg setTo:nil]])
    .andReturn(self.mockFileInfo);
  OCMStub([self.mockFileInfo codesignCheckerWithError:[OCMArg setTo:nil]])
    .andReturn(self.mockCodesignChecker);

  self.mockRuleDatabase = OCMClassMock([SNTRuleTable class]);
  self.mockEventDatabase = OCMClassMock([SNTEventTable class]);

  self.sut = [[SNTExecutionController alloc] initWithEventProvider:self.mockDriverManager
                                                         ruleTable:self.mockRuleDatabase
                                                        eventTable:self.mockEventDatabase
                                                     notifierQueue:nil
                                                        syncdQueue:nil];
}

///  Return a pre-configured santa_message_ t for testing with.
- (santa_message_t)getMessage {
  santa_message_t message = {};
  message.pid = 12;
  message.ppid = 1;
  message.vnode_id = [self getVnodeId];
  strncpy(message.path, "/a/file", 7);
  return message;
}

- (santa_vnode_id_t)getVnodeId {
  return (santa_vnode_id_t){.fsid = 1234, .fileid = 5678};
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

  if (!foundField) {
    XCTFail(@"failed to find %@ field value", expectedFieldValueName);
  }
}

- (void)testBinaryAllowRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;
  OCMStub([self.mockRuleDatabase ruleForBinarySHA256:@"a" certificateSHA256:nil teamID:nil])
    .andReturn(rule);

  [self.sut validateBinaryWithMessage:[self getMessage]];

  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_ALLOW forMessage:[self getMessage]]);
  [self checkMetricCounters:@"AllowBinary" expected:@2];
}

- (void)testBinaryBlockRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateBlock;
  rule.type = SNTRuleTypeBinary;
  OCMStub([self.mockRuleDatabase ruleForBinarySHA256:@"a" certificateSHA256:nil teamID:nil])
    .andReturn(rule);

  [self.sut validateBinaryWithMessage:[self getMessage]];

  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_DENY forMessage:[self getMessage]]);

  // verify that we're incrementing the binary block
  [self checkMetricCounters:@"BlockBinary" expected:@1];
}

- (void)testCertificateAllowRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);

  id cert = OCMClassMock([MOLCertificate class]);
  OCMStub([self.mockCodesignChecker leafCertificate]).andReturn(cert);
  OCMStub([cert SHA256]).andReturn(@"a");

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeCertificate;
  OCMStub([self.mockRuleDatabase ruleForBinarySHA256:nil certificateSHA256:@"a" teamID:nil])
    .andReturn(rule);

  [self.sut validateBinaryWithMessage:[self getMessage]];

  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_ALLOW forMessage:[self getMessage]]);
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
  OCMStub([self.mockRuleDatabase ruleForBinarySHA256:nil certificateSHA256:@"a" teamID:nil])
    .andReturn(rule);

  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self.sut validateBinaryWithMessage:[self getMessage]];

  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_DENY forMessage:[self getMessage]]);
  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:@"BlockCertificate" expected:@1];
}

- (void)testBinaryAllowCompilerRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeBinary;
  OCMStub([self.mockRuleDatabase ruleForBinarySHA256:@"a" certificateSHA256:nil teamID:nil])
    .andReturn(rule);

  [self.sut validateBinaryWithMessage:[self getMessage]];

  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_ALLOW_COMPILER
                                    forMessage:[self getMessage]]);
  [self checkMetricCounters:kAllowCompiler expected:@1];
}

- (void)testBinaryAllowCompilerRuleDisabled {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(NO);

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeBinary;
  OCMStub([self.mockRuleDatabase ruleForBinarySHA256:@"a" certificateSHA256:nil teamID:nil])
    .andReturn(rule);

  [self.sut validateBinaryWithMessage:[self getMessage]];

  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_ALLOW forMessage:[self getMessage]]);
  [self checkMetricCounters:kAllowBinary expected:@1];
}

- (void)testBinaryAllowTransitiveRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowTransitive;
  rule.type = SNTRuleTypeBinary;
  OCMStub([self.mockRuleDatabase ruleForBinarySHA256:@"a" certificateSHA256:nil teamID:nil])
    .andReturn(rule);

  [self.sut validateBinaryWithMessage:[self getMessage]];

  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_ALLOW forMessage:[self getMessage]]);

  [self checkMetricCounters:@"AllowBinary" expected:@2];
}

- (void)testBinaryAllowTransitiveRuleDisabled {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(NO);

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowTransitive;
  rule.type = SNTRuleTypeBinary;
  OCMStub([self.mockRuleDatabase ruleForBinarySHA256:@"a" certificateSHA256:nil teamID:nil])
    .andReturn(rule);

  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self.sut validateBinaryWithMessage:[self getMessage]];

  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_DENY forMessage:[self getMessage]]);
  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kAllowBinary expected:@2];
  [self checkMetricCounters:kAllowTransitive expected:@1];
}

- (void)testDefaultDecision {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  OCMExpect([self.mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self.sut validateBinaryWithMessage:[self getMessage]];
  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_ALLOW forMessage:[self getMessage]]);

  OCMExpect([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  [self.sut validateBinaryWithMessage:[self getMessage]];
  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_DENY forMessage:[self getMessage]]);
  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);

  [self checkMetricCounters:kBlockUnknown expected:@2];
  [self checkMetricCounters:kAllowUnknown expected:@1];
}

- (void)testUnreadableFailOpenLockdown {
  // Undo the default mocks
  [self.mockFileInfo stopMocking];
  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);

  OCMStub([self.mockFileInfo alloc]).andReturn(nil);
  OCMStub([self.mockFileInfo initWithPath:OCMOCK_ANY error:[OCMArg setTo:nil]]).andReturn(nil);

  // Lockdown mode, no fail-closed
  OCMStub([self.mockConfigurator failClosed]).andReturn(NO);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  [self.sut validateBinaryWithMessage:[self getMessage]];
  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_ALLOW forMessage:[self getMessage]]);
  [self checkMetricCounters:kAllowNoFileInfo expected:@2];
}

- (void)testUnreadableFailClosedLockdown {
  // Undo the default mocks
  [self.mockFileInfo stopMocking];
  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);

  OCMStub([self.mockFileInfo alloc]).andReturn(nil);
  OCMStub([self.mockFileInfo initWithPath:OCMOCK_ANY error:[OCMArg setTo:nil]]).andReturn(nil);

  // Lockdown mode, fail-closed
  OCMStub([self.mockConfigurator failClosed]).andReturn(YES);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  [self.sut validateBinaryWithMessage:[self getMessage]];
  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_DENY forMessage:[self getMessage]]);
  [self checkMetricCounters:kDenyNoFileInfo expected:@1];
}

- (void)testUnreadableFailClosedMonitor {
  // Undo the default mocks
  [self.mockFileInfo stopMocking];
  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);

  OCMStub([self.mockFileInfo alloc]).andReturn(nil);
  OCMStub([self.mockFileInfo initWithPath:OCMOCK_ANY error:[OCMArg setTo:nil]]).andReturn(nil);

  // Monitor mode, fail-closed
  OCMStub([self.mockConfigurator failClosed]).andReturn(YES);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  [self.sut validateBinaryWithMessage:[self getMessage]];
  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_ALLOW forMessage:[self getMessage]]);
  [self checkMetricCounters:kAllowNoFileInfo expected:@1];
}

- (void)testMissingShasum {
  [self.sut validateBinaryWithMessage:[self getMessage]];
  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_ALLOW forMessage:[self getMessage]]);
  [self checkMetricCounters:kAllowScope expected:@1];
}

- (void)testOutOfScope {
  OCMStub([self.mockFileInfo isMachO]).andReturn(NO);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  [self.sut validateBinaryWithMessage:[self getMessage]];
  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_ALLOW forMessage:[self getMessage]]);
  [self checkMetricCounters:kAllowScope expected:@2];
}

- (void)testPageZero {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo isMissingPageZero]).andReturn(YES);
  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);
  [self.sut validateBinaryWithMessage:[self getMessage]];
  OCMVerify([self.mockDriverManager postAction:ACTION_RESPOND_DENY forMessage:[self getMessage]]);
  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kBlockUnknown expected:@3];
}

@end
