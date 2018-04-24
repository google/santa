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

@import XCTest;

#import <OCMock/OCMock.h>

#import "SNTExecutionController.h"

#import "MOLCertificate.h"
#import "MOLCodesignChecker.h"
#import "SNTConfigurator.h"
#import "SNTDriverManager.h"
#import "SNTEventTable.h"
#import "SNTFileInfo.h"
#import "SNTRule.h"
#import "SNTRuleTable.h"

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

  OCMStub([self.mockCodesignChecker initWithBinaryPath:OCMOCK_ANY
                                        fileDescriptor:0
                                                 error:[OCMArg setTo:NULL]])
      .andReturn(self.mockCodesignChecker);

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  self.mockDriverManager = OCMClassMock([SNTDriverManager class]);

  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([self.mockFileInfo alloc]).andReturn(self.mockFileInfo);
  OCMStub([self.mockFileInfo initWithPath:OCMOCK_ANY
                                    error:[OCMArg setTo:nil]]).andReturn(self.mockFileInfo);

  self.mockRuleDatabase = OCMClassMock([SNTRuleTable class]);
  self.mockEventDatabase = OCMClassMock([SNTEventTable class]);

  self.sut = [[SNTExecutionController alloc] initWithDriverManager:self.mockDriverManager
                                                         ruleTable:self.mockRuleDatabase
                                                        eventTable:self.mockEventDatabase
                                                     notifierQueue:nil
                                                        syncdQueue:nil
                                                          eventLog:nil];
}

///  Return a pre-configured santa_message_ t for testing with.
- (santa_message_t)getMessage {
  santa_message_t message = {0};
  message.pid = 12;
  message.ppid = 1;
  message.vnode_id = 1234;
  strncpy(message.path, "/a/file", 7);
  return message;
}

- (void)tearDown {
  [self.mockFileInfo stopMocking];
  [self.mockCodesignChecker stopMocking];
  [self.mockDriverManager stopMocking];
  [self.mockRuleDatabase stopMocking];
  [self.mockEventDatabase stopMocking];

  [super tearDown];
}

- (void)testBinaryWhitelistRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateWhitelist;
  rule.type = SNTRuleTypeBinary;
  OCMStub([self.mockRuleDatabase ruleForBinarySHA256:@"a" certificateSHA256:nil]).andReturn(rule);

  [self.sut validateBinaryWithMessage:[self getMessage]];

  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_ALLOW
                                            forVnodeID:1234]);
}

- (void)testBinaryBlacklistRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateBlacklist;
  rule.type = SNTRuleTypeBinary;
  OCMStub([self.mockRuleDatabase ruleForBinarySHA256:@"a" certificateSHA256:nil]).andReturn(rule);

  [self.sut validateBinaryWithMessage:[self getMessage]];

  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_DENY
                                            forVnodeID:1234]);
}

- (void)testCertificateWhitelistRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);

  id cert = OCMClassMock([MOLCertificate class]);
  OCMStub([self.mockCodesignChecker leafCertificate]).andReturn(cert);
  OCMStub([cert SHA256]).andReturn(@"a");

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateWhitelist;
  rule.type = SNTRuleTypeCertificate;
  OCMStub([self.mockRuleDatabase ruleForBinarySHA256:nil certificateSHA256:@"a"]).andReturn(rule);

  [self.sut validateBinaryWithMessage:[self getMessage]];

  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_ALLOW
                                            forVnodeID:1234]);
}

- (void)testCertificateBlacklistRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);

  id cert = OCMClassMock([MOLCertificate class]);
  OCMStub([self.mockCodesignChecker leafCertificate]).andReturn(cert);
  OCMStub([cert SHA256]).andReturn(@"a");

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateBlacklist;
  rule.type = SNTRuleTypeCertificate;
  OCMStub([self.mockRuleDatabase ruleForBinarySHA256:nil certificateSHA256:@"a"]).andReturn(rule);

  [self.sut validateBinaryWithMessage:[self getMessage]];

  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_DENY
                                            forVnodeID:1234]);
}

- (void)testDefaultDecision {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  OCMExpect([self.mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  [self.sut validateBinaryWithMessage:[self getMessage]];
  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_ALLOW
                                            forVnodeID:1234]);

  OCMExpect([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  [self.sut validateBinaryWithMessage:[self getMessage]];
  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_DENY
                                            forVnodeID:1234]);
}

- (void)testOutOfScope {
  OCMStub([self.mockFileInfo isMachO]).andReturn(NO);

  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  [self.sut validateBinaryWithMessage:[self getMessage]];
  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_ALLOW
                                            forVnodeID:1234]);
}

- (void)testMissingShasum {
  [self.sut validateBinaryWithMessage:[self getMessage]];
  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_ALLOW
                                            forVnodeID:1234]);
}

- (void)testPageZero {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo isMissingPageZero]).andReturn(YES);

  [self.sut validateBinaryWithMessage:[self getMessage]];
  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_DENY
                                            forVnodeID:1234]);
}

@end
