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

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "SNTExecutionController.h"

#import "SNTCertificate.h"
#import "SNTCodesignChecker.h"
#import "SNTDriverManager.h"
#import "SNTEventTable.h"
#import "SNTFileInfo.h"
#import "SNTRule.h"
#import "SNTRuleTable.h"

@interface SNTExecutionController (Testing)
- (BOOL)fileIsInScope:(NSString *)path;
@end

@interface SNTExecutionControllerTest : XCTestCase
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

  self.mockCodesignChecker = OCMClassMock([SNTCodesignChecker class]);
  self.mockDriverManager = OCMClassMock([SNTDriverManager class]);
  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);  
  self.mockRuleDatabase = OCMClassMock([SNTRuleTable class]);
  self.mockEventDatabase = OCMClassMock([SNTEventTable class]);

  self.sut = [[SNTExecutionController alloc] initWithDriverManager:self.mockDriverManager
                                                         ruleTable:self.mockRuleDatabase
                                                        eventTable:self.mockEventDatabase
                                                     operatingMode:CLIENTMODE_MONITOR
                                                notifierConnection:nil];
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
  id mockSut = OCMPartialMock(self.sut);
  OCMStub([mockSut fileIsInScope:OCMOCK_ANY]).andReturn(YES);

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = RULESTATE_WHITELIST;
  OCMStub([self.mockRuleDatabase binaryRuleForSHA256:@"a"]).andReturn(rule);

  [self.sut validateBinaryWithPath:@"/a/file"
                          userName:@"nobody"
                               pid:@(12)
                           vnodeId:1234];

  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_CHECKBW_ALLOW
                                            forVnodeID:1234]);
}

- (void)testBinaryBlacklistRule {
  id mockSut = OCMPartialMock(self.sut);
  OCMStub([mockSut fileIsInScope:OCMOCK_ANY]).andReturn(YES);

  [[[self.mockFileInfo stub] andReturn:self.mockFileInfo] alloc];
  (void)[[[self.mockFileInfo stub] andReturn:self.mockFileInfo] initWithPath:[OCMArg any]];
  [[[self.mockFileInfo stub] andReturn:@"a"] SHA256];

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = RULESTATE_BLACKLIST;
  OCMStub([self.mockRuleDatabase binaryRuleForSHA256:@"a"]).andReturn(rule);

  [self.sut validateBinaryWithPath:@"/a/file"
                          userName:@"nobody"
                               pid:@(12)
                           vnodeId:1234];

  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_CHECKBW_DENY
                                            forVnodeID:1234]);
}

- (void)testCertificateWhitelistRule {
  id mockSut = OCMPartialMock(self.sut);
  OCMStub([mockSut fileIsInScope:OCMOCK_ANY]).andReturn(YES);

  id cert = OCMClassMock([SNTCertificate class]);
  OCMStub([self.mockCodesignChecker alloc]).andReturn(self.mockCodesignChecker);
  OCMStub([self.mockCodesignChecker initWithBinaryPath:OCMOCK_ANY])
      .andReturn(self.mockCodesignChecker);
  OCMStub([self.mockCodesignChecker leafCertificate]).andReturn(cert);
  OCMStub([cert SHA1]).andReturn(@"a");

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = RULESTATE_WHITELIST;
  OCMStub([self.mockRuleDatabase certificateRuleForSHA1:@"a"]).andReturn(rule);

  [self.sut validateBinaryWithPath:@"/a/file"
                          userName:@"nobody"
                               pid:@(12)
                           vnodeId:1234];

  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_CHECKBW_ALLOW
                                            forVnodeID:1234]);
}

- (void)testCertificateBlacklistRule {
  id mockSut = OCMPartialMock(self.sut);
  OCMStub([mockSut fileIsInScope:OCMOCK_ANY]).andReturn(YES);

  id cert = OCMClassMock([SNTCertificate class]);
  OCMStub([self.mockCodesignChecker alloc]).andReturn(self.mockCodesignChecker);
  OCMStub([self.mockCodesignChecker initWithBinaryPath:OCMOCK_ANY])
    .andReturn(self.mockCodesignChecker);
  OCMStub([self.mockCodesignChecker leafCertificate]).andReturn(cert);
  OCMStub([cert SHA1]).andReturn(@"a");

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = RULESTATE_BLACKLIST;
  OCMStub([self.mockRuleDatabase certificateRuleForSHA1:@"a"]).andReturn(rule);

  [self.sut validateBinaryWithPath:@"/a/file"
                          userName:@"nobody"
                               pid:@(12)
                           vnodeId:1234];

  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_CHECKBW_DENY
                                            forVnodeID:1234]);
}

- (void)testDefaultDecision {
  id mockSut = OCMPartialMock(self.sut);
  OCMStub([mockSut fileIsInScope:OCMOCK_ANY]).andReturn(YES);

  [self.sut setOperatingMode:CLIENTMODE_MONITOR];
  [self.sut validateBinaryWithPath:@"/a/file"
                          userName:@"nobody"
                               pid:@(12)
                           vnodeId:1234];
  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_CHECKBW_ALLOW
                                            forVnodeID:1234]);

  [self.sut setOperatingMode:CLIENTMODE_LOCKDOWN];
  [self.sut validateBinaryWithPath:@"/a/file"
                          userName:@"nobody"
                               pid:@(12)
                           vnodeId:1234];
  OCMVerify([self.mockDriverManager postToKernelAction:ACTION_RESPOND_CHECKBW_DENY
                                            forVnodeID:1234]);
}

- (void)testOutOfScope {
  id mockSut = OCMPartialMock(self.sut);
  OCMStub([mockSut fileIsInScope:OCMOCK_ANY]).andReturn(NO);

}

@end
