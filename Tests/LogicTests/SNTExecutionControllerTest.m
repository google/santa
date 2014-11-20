/// Copyright 2014 Google Inc. All rights reserved.
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

#import "SNTBinaryInfo.h"
#import "SNTCertificate.h"
#import "SNTCodesignChecker.h"
#import "SNTDriverManager.h"
#import "SNTEventTable.h"
#import "SNTNotificationMessage.h"
#import "SNTRule.h"
#import "SNTRuleTable.h"

@interface SNTExecutionController (Testing)
- (BOOL)fileIsInScope:(NSString *)path;
@end

@interface SNTExecutionControllerTest : XCTestCase
@property id mockBinaryInfo;
@property id mockCodesignChecker;
@property id mockDriverManager;
@property id mockRuleDatabase;
@property id mockEventDatabase;

@property SNTExecutionController *sut;
@end

@implementation SNTExecutionControllerTest

- (void)setUp {
  [super setUp];

  fclose(stdout);

  self.mockBinaryInfo = [OCMockObject niceMockForClass:[SNTBinaryInfo class]];
  self.mockCodesignChecker = [OCMockObject niceMockForClass:[SNTCodesignChecker class]];
  self.mockDriverManager = [OCMockObject niceMockForClass:[SNTDriverManager class]];
  self.mockRuleDatabase = [OCMockObject niceMockForClass:[SNTRuleTable class]];
  self.mockEventDatabase = [OCMockObject niceMockForClass:[SNTEventTable class]];

  self.sut = [[SNTExecutionController alloc] initWithDriverManager:self.mockDriverManager
                                                         ruleTable:self.mockRuleDatabase
                                                        eventTable:self.mockEventDatabase
                                                     operatingMode:CLIENTMODE_MONITOR
                                                notifierConnection:nil];
}

- (void)tearDown {
  [self.mockBinaryInfo verify];
  [self.mockCodesignChecker verify];
  [self.mockDriverManager verify];
  [self.mockRuleDatabase verify];
  [self.mockEventDatabase verify];

  [self.mockBinaryInfo stopMocking];
  [self.mockCodesignChecker stopMocking];
  [self.mockDriverManager stopMocking];
  [self.mockRuleDatabase stopMocking];
  [self.mockEventDatabase stopMocking];

  [super tearDown];
}

- (void)testBinaryWhitelistRule {
  id mockSut = [OCMockObject partialMockForObject:self.sut];
  [[[mockSut stub] andReturnValue:OCMOCK_VALUE(YES)] fileIsInScope:OCMOCK_ANY];

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = RULESTATE_WHITELIST;
  [[[self.mockRuleDatabase stub] andReturn:rule] binaryRuleForSHA1:@"a"];

  [[self.mockDriverManager expect] postToKernelAction:ACTION_RESPOND_CHECKBW_ALLOW
                                            forVnodeID:1234];

  [self.sut validateBinaryWithSHA1:@"a"
                              path:@"/a/file"
                          userName:@"nobody"
                               pid:@(12)
                           vnodeId:1234];
}

- (void)testBinaryBlacklistRule {
  id mockSut = [OCMockObject partialMockForObject:self.sut];
  [[[mockSut stub] andReturnValue:OCMOCK_VALUE(YES)] fileIsInScope:OCMOCK_ANY];

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = RULESTATE_BLACKLIST;
  [[[self.mockRuleDatabase stub] andReturn:rule] binaryRuleForSHA1:@"a"];

  [[self.mockDriverManager expect] postToKernelAction:ACTION_RESPOND_CHECKBW_DENY
                                           forVnodeID:1234];

  [self.sut validateBinaryWithSHA1:@"a"
                              path:@"/a/file"
                          userName:@"nobody"
                               pid:@(12)
                           vnodeId:1234];
}

- (void)testCertificateWhitelistRule {
  id mockSut = [OCMockObject partialMockForObject:self.sut];
  [[[mockSut stub] andReturnValue:OCMOCK_VALUE(YES)] fileIsInScope:OCMOCK_ANY];

  id cert = [OCMockObject niceMockForClass:[SNTCertificate class]];
  [[[self.mockCodesignChecker stub] andReturn:self.mockCodesignChecker] alloc];
  (void)[[[self.mockCodesignChecker stub] andReturn:self.mockCodesignChecker]
         initWithBinaryPath:[OCMArg any]];
  [[[self.mockCodesignChecker stub] andReturn:cert] leafCertificate];
  [[[cert stub] andReturn:@"a"] SHA1];

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = RULESTATE_WHITELIST;
  [[[self.mockRuleDatabase stub] andReturn:rule] certificateRuleForSHA1:@"a"];

  [[self.mockDriverManager expect] postToKernelAction:ACTION_RESPOND_CHECKBW_ALLOW
                                           forVnodeID:1234];

  [self.sut validateBinaryWithSHA1:@"a"
                              path:@"/a/file"
                          userName:@"nobody"
                               pid:@(12)
                           vnodeId:1234];
}

- (void)testCertificateBlacklistRule {
  id mockSut = [OCMockObject partialMockForObject:self.sut];
  [[[mockSut stub] andReturnValue:OCMOCK_VALUE(YES)] fileIsInScope:OCMOCK_ANY];

  id cert = [OCMockObject niceMockForClass:[SNTCertificate class]];
  [[[self.mockCodesignChecker stub] andReturn:self.mockCodesignChecker] alloc];
  (void)[[[self.mockCodesignChecker stub] andReturn:self.mockCodesignChecker]
         initWithBinaryPath:[OCMArg any]];
  [[[self.mockCodesignChecker stub] andReturn:cert] leafCertificate];
  [[[cert stub] andReturn:@"a"] SHA1];

  SNTRule *rule = [[SNTRule alloc] init];
  rule.state = RULESTATE_BLACKLIST;
  [[[self.mockRuleDatabase stub] andReturn:rule] certificateRuleForSHA1:@"a"];

  [[self.mockDriverManager expect] postToKernelAction:ACTION_RESPOND_CHECKBW_DENY
                                           forVnodeID:1234];

  [self.sut validateBinaryWithSHA1:@"a"
                              path:@"/a/file"
                          userName:@"nobody"
                               pid:@(12)
                           vnodeId:1234];
}

- (void)testDefaultDecision {
  id mockSut = [OCMockObject partialMockForObject:self.sut];
  [[[mockSut stub] andReturnValue:OCMOCK_VALUE(YES)] fileIsInScope:OCMOCK_ANY];

  [self.sut setOperatingMode:CLIENTMODE_MONITOR];
  [[self.mockDriverManager expect] postToKernelAction:ACTION_RESPOND_CHECKBW_ALLOW
                                              forVnodeID:1234];
  [self.sut validateBinaryWithSHA1:@"a"
                              path:@"/a/file"
                          userName:@"nobody"
                               pid:@(12)
                           vnodeId:1234];

  [self.sut setOperatingMode:CLIENTMODE_LOCKDOWN];
  [[self.mockDriverManager expect] postToKernelAction:ACTION_RESPOND_CHECKBW_DENY
                                              forVnodeID:1234];
  [self.sut validateBinaryWithSHA1:@"a"
                              path:@"/a/file"
                          userName:@"nobody"
                               pid:@(12)
                           vnodeId:1234];

}

@end
