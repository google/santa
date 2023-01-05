/// Copyright 2022 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include <EndpointSecurity/EndpointSecurity.h>
#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/fcntl.h>

#include <array>
#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <variant>

#include "Source/common/Platform.h"
#include "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/DataLayer/WatchItems.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityFileAccessAuthorizer.h"
#include "Source/santad/Logs/EndpointSecurity/MockLogger.h"
#include "Source/santad/SNTDecisionCache.h"

using santa::santad::data_layer::WatchItemPolicy;
using santa::santad::event_providers::endpoint_security::Message;

extern NSString *kBadCertHash;

// Duplicate definition for test implementation
struct PathTarget {
  std::string path;
  bool isReadable;
};

using PathTargetsPair = std::pair<std::optional<std::string>, std::optional<std::string>>;
extern void PopulatePathTargets(const Message &msg, std::vector<PathTarget> &targets);
extern es_auth_result_t FileAccessPolicyDecisionToESAuthResult(FileAccessPolicyDecision decision);
extern bool ShouldLogDecision(FileAccessPolicyDecision decision);
extern es_auth_result_t CombinePolicyResults(es_auth_result_t result1, es_auth_result_t result2);

void SetExpectationsForFileAccessAuthorizerInit(
  std::shared_ptr<MockEndpointSecurityAPI> mockESApi) {
  EXPECT_CALL(*mockESApi, InvertTargetPathMuting).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, UnmuteAllPaths).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, UnmuteAllTargetPaths).WillOnce(testing::Return(true));
}

@interface SNTEndpointSecurityFileAccessAuthorizer (Testing)
- (NSString *)getCertificateHash:(es_file_t *)esFile;
- (FileAccessPolicyDecision)specialCaseForPolicy:(std::shared_ptr<WatchItemPolicy>)policy
                                          target:(const PathTarget &)target
                                         message:(const Message &)msg;
- (FileAccessPolicyDecision)applyPolicy:
                              (std::optional<std::shared_ptr<WatchItemPolicy>>)optionalPolicy
                              forTarget:(const PathTarget &)target
                              toMessage:(const Message &)msg;

@property bool isSubscribed;
@end

@interface SNTEndpointSecurityFileAccessAuthorizerTest : XCTestCase
@property id mockConfigurator;
@property id cscMock;
@property id dcMock;
@end

@implementation SNTEndpointSecurityFileAccessAuthorizerTest

- (void)setUp {
  [super setUp];

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  self.cscMock = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([self.cscMock alloc]).andReturn(self.cscMock);

  self.dcMock = OCMStrictClassMock([SNTDecisionCache class]);
}

- (void)tearDown {
  [self.cscMock stopMocking];
  [self.dcMock stopMocking];

  [super tearDown];
}

- (void)testGetCertificateHash {
  es_file_t esFile1 = MakeESFile("foo", MakeStat(100));
  es_file_t esFile2 = MakeESFile("foo", MakeStat(200));
  es_file_t esFile3 = MakeESFile("foo", MakeStat(300));
  NSString *certHash2 = @"abc123";
  NSString *certHash3 = @"xyz789";
  NSString *got;
  NSString *want;
  id certMock = OCMClassMock([MOLCertificate class]);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  SetExpectationsForFileAccessAuthorizerInit(mockESApi);

  SNTEndpointSecurityFileAccessAuthorizer *accessClient =
    [[SNTEndpointSecurityFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                           metrics:nullptr
                                                            logger:nullptr
                                                        watchItems:nullptr
                                                          enricher:nullptr
                                                     decisionCache:self.dcMock];

  //
  // Test 1 - Not in local cache or decision cache, and code sig lookup fails
  //
  OCMExpect([self.dcMock cachedDecisionForFile:esFile1.stat])
    .ignoringNonObjectArgs()
    .andReturn(nil);

  NSError *err = [NSError errorWithDomain:@"" code:errSecCSSignatureFailed userInfo:nil];
  OCMExpect([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
    .andReturn(self.cscMock);

  got = [accessClient getCertificateHash:&esFile1];
  want = kBadCertHash;

  XCTAssertEqualObjects(got, want);

  // Call again without setting new expectations on dcMock to ensure the
  // cached value is used
  got = [accessClient getCertificateHash:&esFile1];
  XCTAssertEqualObjects(got, want);

  XCTAssertTrue(OCMVerifyAll(self.dcMock));

  //
  // Test 2 - Not in local cache or decision cache, code sig lookup successful
  //
  OCMExpect([self.dcMock cachedDecisionForFile:esFile2.stat])
    .ignoringNonObjectArgs()
    .andReturn(nil);
  OCMExpect([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:nil]])
    .andReturn(self.cscMock);

  OCMExpect([self.cscMock leafCertificate]).andReturn(certMock);
  OCMExpect([certMock SHA256]).andReturn(certHash2);

  got = [accessClient getCertificateHash:&esFile2];
  want = certHash2;

  XCTAssertEqualObjects(got, want);

  // Call again without setting new expectations on dcMock to ensure the
  // cached value is used
  got = [accessClient getCertificateHash:&esFile2];
  XCTAssertEqualObjects(got, want);

  XCTAssertTrue(OCMVerifyAll(self.dcMock));

  //
  // Test 3 - Not in local cache, but is in decision cache
  //
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.certSHA256 = certHash3;
  OCMExpect([self.dcMock cachedDecisionForFile:esFile3.stat]).ignoringNonObjectArgs().andReturn(cd);

  got = [accessClient getCertificateHash:&esFile3];
  want = certHash3;

  XCTAssertEqualObjects(got, want);

  // Call again without setting new expectations on dcMock to ensure the
  // cached value is used
  got = [accessClient getCertificateHash:&esFile3];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  [certMock stopMocking];
}

- (void)testFileAccessPolicyDecisionToESAuthResult {
  std::map<FileAccessPolicyDecision, es_auth_result_t> policyDecisionToAuthResult = {
    {FileAccessPolicyDecision::kNoPolicy, ES_AUTH_RESULT_ALLOW},
    {FileAccessPolicyDecision::kDenied, ES_AUTH_RESULT_DENY},
    {FileAccessPolicyDecision::kDeniedInvalidSignature, ES_AUTH_RESULT_DENY},
    {FileAccessPolicyDecision::kAllowed, ES_AUTH_RESULT_ALLOW},
    {FileAccessPolicyDecision::kAllowedReadAccess, ES_AUTH_RESULT_ALLOW},
    {FileAccessPolicyDecision::kAllowedAuditOnly, ES_AUTH_RESULT_ALLOW},
  };

  for (const auto &kv : policyDecisionToAuthResult) {
    XCTAssertEqual(FileAccessPolicyDecisionToESAuthResult(kv.first), kv.second);
  }

  XCTAssertThrows(FileAccessPolicyDecisionToESAuthResult((FileAccessPolicyDecision)123));
}

- (void)testShouldLogDecision {
  std::map<FileAccessPolicyDecision, bool> policyDecisionToShouldLog = {
    {FileAccessPolicyDecision::kNoPolicy, false},
    {FileAccessPolicyDecision::kDenied, true},
    {FileAccessPolicyDecision::kDeniedInvalidSignature, true},
    {FileAccessPolicyDecision::kAllowed, false},
    {FileAccessPolicyDecision::kAllowedReadAccess, false},
    {FileAccessPolicyDecision::kAllowedAuditOnly, true},
    {(FileAccessPolicyDecision)5, false},
  };

  for (const auto &kv : policyDecisionToShouldLog) {
    XCTAssertEqual(ShouldLogDecision(kv.first), kv.second);
  }
}

- (void)testCombinePolicyResults {
  // Ensure that the combined result is ES_AUTH_RESULT_DENY if both or either
  // input result is ES_AUTH_RESULT_DENY.
  XCTAssertEqual(CombinePolicyResults(ES_AUTH_RESULT_DENY, ES_AUTH_RESULT_DENY),
                 ES_AUTH_RESULT_DENY);

  XCTAssertEqual(CombinePolicyResults(ES_AUTH_RESULT_DENY, ES_AUTH_RESULT_ALLOW),
                 ES_AUTH_RESULT_DENY);

  XCTAssertEqual(CombinePolicyResults(ES_AUTH_RESULT_ALLOW, ES_AUTH_RESULT_DENY),
                 ES_AUTH_RESULT_DENY);

  XCTAssertEqual(CombinePolicyResults(ES_AUTH_RESULT_ALLOW, ES_AUTH_RESULT_ALLOW),
                 ES_AUTH_RESULT_ALLOW);
}

- (void)testSpecialCaseForPolicyMessage {
  es_file_t esFile = MakeESFile("foo");
  es_process_t esProc = MakeESProcess(&esFile);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_OPEN, &esProc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();
  SetExpectationsForFileAccessAuthorizerInit(mockESApi);

  SNTEndpointSecurityFileAccessAuthorizer *accessClient =
    [[SNTEndpointSecurityFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                           metrics:nullptr
                                                            logger:nullptr
                                                        watchItems:nullptr
                                                          enricher:nullptr
                                                     decisionCache:nil];

  auto policy = std::make_shared<WatchItemPolicy>("foo_policy", "/foo");

  FileAccessPolicyDecision result;
  PathTarget target = {.path = "/some/random/path", .isReadable = true};

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_OPEN;

    // Write-only policy, Write operation
    {
      policy->write_only = true;
      esMsg.event.open.fflag = FWRITE | FREAD;
      Message msg(mockESApi, &esMsg);
      result = [accessClient specialCaseForPolicy:policy target:target message:msg];
      XCTAssertEqual(result, FileAccessPolicyDecision::kNoPolicy);
    }

    // Write-only policy, Read operation
    {
      policy->write_only = true;
      esMsg.event.open.fflag = FREAD;
      Message msg(mockESApi, &esMsg);
      result = [accessClient specialCaseForPolicy:policy target:target message:msg];
      XCTAssertEqual(result, FileAccessPolicyDecision::kAllowedReadAccess);
    }

    // Read/Write policy, Read operation
    {
      policy->write_only = false;
      esMsg.event.open.fflag = FREAD;
      Message msg(mockESApi, &esMsg);
      result = [accessClient specialCaseForPolicy:policy target:target message:msg];
      XCTAssertEqual(result, FileAccessPolicyDecision::kNoPolicy);
    }
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_CLONE;

    // Write-only policy, target readable
    {
      policy->write_only = true;
      target.isReadable = true;
      Message msg(mockESApi, &esMsg);
      result = [accessClient specialCaseForPolicy:policy target:target message:msg];
      XCTAssertEqual(result, FileAccessPolicyDecision::kAllowedReadAccess);
    }

    // Write-only policy, target not readable
    {
      policy->write_only = true;
      target.isReadable = false;
      Message msg(mockESApi, &esMsg);
      result = [accessClient specialCaseForPolicy:policy target:target message:msg];
      XCTAssertEqual(result, FileAccessPolicyDecision::kNoPolicy);
    }
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_COPYFILE;

    // Write-only policy, target readable
    {
      policy->write_only = true;
      target.isReadable = true;
      Message msg(mockESApi, &esMsg);
      result = [accessClient specialCaseForPolicy:policy target:target message:msg];
      XCTAssertEqual(result, FileAccessPolicyDecision::kAllowedReadAccess);
    }

    // Write-only policy, target not readable
    {
      policy->write_only = true;
      target.isReadable = false;
      Message msg(mockESApi, &esMsg);
      result = [accessClient specialCaseForPolicy:policy target:target message:msg];
      XCTAssertEqual(result, FileAccessPolicyDecision::kNoPolicy);
    }
  }

  // Ensure other handled event types do not have a special case
  std::set<es_event_type_t> eventTypes = {
    ES_EVENT_TYPE_AUTH_CREATE, ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_LINK,
    ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_TRUNCATE,     ES_EVENT_TYPE_AUTH_UNLINK,
  };

  for (const auto &event : eventTypes) {
    esMsg.event_type = event;
    Message msg(mockESApi, &esMsg);
    result = [accessClient specialCaseForPolicy:policy target:target message:msg];
    XCTAssertEqual(result, FileAccessPolicyDecision::kNoPolicy);
  }

  // Ensure unsubscribed event types throw an exception
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_SIGNAL;
    Message msg(mockESApi, &esMsg);
    XCTAssertThrows([accessClient specialCaseForPolicy:policy target:target message:msg]);
  }
}

- (void)testApplyPolicyToMessage {
  const char *instigatingPath = "/path/to/proc";
  const char *instigatingTeamID = "my_teamid";
  const char *instigatingCertHash = "abc123";
  std::array<uint8_t, 20> instigatingCDHash;
  instigatingCDHash.fill(0x41);
  es_file_t esFile = MakeESFile(instigatingPath);
  es_process_t esProc = MakeESProcess(&esFile);
  esProc.team_id = MakeESStringToken(instigatingTeamID);
  memcpy(esProc.cdhash, instigatingCDHash.data(), sizeof(esProc.cdhash));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_OPEN, &esProc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();
  SetExpectationsForFileAccessAuthorizerInit(mockESApi);

  SNTEndpointSecurityFileAccessAuthorizer *accessClient =
    [[SNTEndpointSecurityFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                           metrics:nullptr
                                                            logger:nullptr
                                                        watchItems:nullptr
                                                          enricher:nullptr
                                                     decisionCache:nil];

  id accessClientMock = OCMPartialMock(accessClient);

  PathTarget target = {.path = "/some/random/path", .isReadable = true};
  int fake;
  OCMStub([accessClientMock specialCaseForPolicy:nullptr target:target message:*(Message *)&fake])
    .ignoringNonObjectArgs()
    .andReturn(FileAccessPolicyDecision::kNoPolicy);

  OCMStub([accessClientMock getCertificateHash:&esFile])
    .ignoringNonObjectArgs()
    .andReturn(@(instigatingCertHash));

  // If no policy exists, the operation is allowed
  {
    Message msg(mockESApi, &esMsg);
    XCTAssertEqual([accessClient applyPolicy:std::nullopt forTarget:target toMessage:msg],
                   FileAccessPolicyDecision::kNoPolicy);
  }

  auto policy = std::make_shared<WatchItemPolicy>("foo_policy", "/foo");
  auto optionalPolicy = std::make_optional<std::shared_ptr<WatchItemPolicy>>(policy);

  // Signed but invalid instigating processes are automatically
  // denied when `EnableBadSignatureProtection` is true
  {
    OCMExpect([self.mockConfigurator enableBadSignatureProtection]).andReturn(YES);
    esMsg.process->codesigning_flags = CS_SIGNED;
    Message msg(mockESApi, &esMsg);
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy forTarget:target toMessage:msg],
                   FileAccessPolicyDecision::kDeniedInvalidSignature);
  }

  // Signed but invalid instigating processes are not automatically
  // denied when `EnableBadSignatureProtection` is false. Policy
  // evaluation should continue normally.
  {
    OCMExpect([self.mockConfigurator enableBadSignatureProtection]).andReturn(NO);
    esMsg.process->codesigning_flags = CS_SIGNED;
    Message msg(mockESApi, &esMsg);
    policy->allowed_binary_paths.insert(instigatingPath);
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy forTarget:target toMessage:msg],
                   FileAccessPolicyDecision::kAllowed);
    policy->allowed_binary_paths.clear();
  }

  // Set the codesign flags to be signed and valid for the remaining tests
  esMsg.process->codesigning_flags = CS_SIGNED | CS_VALID;

  // Test allowed binary paths matching instigator are allowed
  {
    Message msg(mockESApi, &esMsg);
    policy->allowed_binary_paths.insert(instigatingPath);
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy forTarget:target toMessage:msg],
                   FileAccessPolicyDecision::kAllowed);
    policy->allowed_binary_paths.clear();
  }

  // Test allowed TeamIDs matching instigator are allowed
  {
    Message msg(mockESApi, &esMsg);
    policy->allowed_team_ids.insert(instigatingTeamID);
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy forTarget:target toMessage:msg],
                   FileAccessPolicyDecision::kAllowed);
    policy->allowed_team_ids.clear();
  }

  // Test allowed CDHashes matching instigator are allowed
  {
    Message msg(mockESApi, &esMsg);
    policy->allowed_cdhashes.insert(instigatingCDHash);
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy forTarget:target toMessage:msg],
                   FileAccessPolicyDecision::kAllowed);
    policy->allowed_cdhashes.clear();
  }

  // Test allowed cert hashes matching instigator are allowed
  {
    Message msg(mockESApi, &esMsg);
    policy->allowed_certificates_sha256.insert(instigatingCertHash);
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy forTarget:target toMessage:msg],
                   FileAccessPolicyDecision::kAllowed);
    policy->allowed_certificates_sha256.clear();
  }

  // If no exceptions, operations are logged and denied
  {
    policy->audit_only = false;
    Message msg(mockESApi, &esMsg);
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy forTarget:target toMessage:msg],
                   FileAccessPolicyDecision::kDenied);
  }

  // For audit only policies with no exceptions, operations are logged but allowed
  {
    policy->audit_only = true;
    Message msg(mockESApi, &esMsg);
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy forTarget:target toMessage:msg],
                   FileAccessPolicyDecision::kAllowedAuditOnly);
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testEnable {
  std::set<es_event_type_t> expectedEventSubs = {
    ES_EVENT_TYPE_AUTH_CLONE,    ES_EVENT_TYPE_AUTH_CREATE, ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
    ES_EVENT_TYPE_AUTH_LINK,     ES_EVENT_TYPE_AUTH_OPEN,   ES_EVENT_TYPE_AUTH_RENAME,
    ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_UNLINK,
  };

#if HAVE_MACOS_12
  if (@available(macOS 12.0, *)) {
    expectedEventSubs.insert(ES_EVENT_TYPE_AUTH_COPYFILE);
  }
#endif

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, ClearCache)
    .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
             .WillOnce(testing::Return(true)))
    .WillOnce(testing::Return(true));

  id fileAccessClient = [[SNTEndpointSecurityFileAccessAuthorizer alloc]
    initWithESAPI:mockESApi
          metrics:nullptr
        processor:santa::santad::Processor::kFileAccessAuthorizer];

  [fileAccessClient enable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testDisable {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  SetExpectationsForFileAccessAuthorizerInit(mockESApi);

  SNTEndpointSecurityFileAccessAuthorizer *accessClient =
    [[SNTEndpointSecurityFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                           metrics:nullptr
                                                            logger:nullptr
                                                        watchItems:nullptr
                                                          enricher:nullptr
                                                     decisionCache:nil];

  EXPECT_CALL(*mockESApi, UnsubscribeAll);
  EXPECT_CALL(*mockESApi, UnmuteAllPaths).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, UnmuteAllTargetPaths).WillOnce(testing::Return(true));

  accessClient.isSubscribed = true;
  [accessClient disable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testGetPathTargets {
  // This test ensures that the `GetPathTargets` functions returns the
  // expected combination of targets for each handled event variant
  es_file_t testFile1 = MakeESFile("test_file_1");
  es_file_t testFile2 = MakeESFile("test_file_2");
  es_file_t testDir = MakeESFile("test_dir");
  es_string_token_t testTok = MakeESStringToken("test_tok");
  std::string dirTok = std::string(testDir.path.data) + "/" + std::string(testTok.data);

  es_message_t esMsg;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  Message msg(mockESApi, &esMsg);

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_OPEN;
    esMsg.event.open.file = &testFile1;

    std::vector<PathTarget> targets;
    PopulatePathTargets(msg, targets);

    XCTAssertEqual(targets.size(), 1);
    XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
    XCTAssertTrue(targets[0].isReadable);
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_LINK;
    esMsg.event.link.source = &testFile1;
    esMsg.event.link.target_dir = &testDir;
    esMsg.event.link.target_filename = testTok;

    std::vector<PathTarget> targets;
    PopulatePathTargets(msg, targets);

    XCTAssertEqual(targets.size(), 2);
    XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
    XCTAssertFalse(targets[0].isReadable);
    XCTAssertCppStringEqual(targets[1].path, dirTok);
    XCTAssertFalse(targets[1].isReadable);
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_RENAME;
    esMsg.event.rename.source = &testFile1;

    {
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
      esMsg.event.rename.destination.existing_file = &testFile2;

      std::vector<PathTarget> targets;
      PopulatePathTargets(msg, targets);

      XCTAssertEqual(targets.size(), 2);
      XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
      XCTAssertFalse(targets[0].isReadable);
      XCTAssertCStringEqual(targets[1].path.c_str(), testFile2.path.data);
      XCTAssertFalse(targets[1].isReadable);
    }

    {
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
      esMsg.event.rename.destination.new_path.dir = &testDir;
      esMsg.event.rename.destination.new_path.filename = testTok;

      std::vector<PathTarget> targets;
      PopulatePathTargets(msg, targets);

      XCTAssertEqual(targets.size(), 2);
      XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
      XCTAssertFalse(targets[0].isReadable);
      XCTAssertCppStringEqual(targets[1].path, dirTok);
      XCTAssertFalse(targets[1].isReadable);
    }
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_UNLINK;
    esMsg.event.unlink.target = &testFile1;

    std::vector<PathTarget> targets;
    PopulatePathTargets(msg, targets);

    XCTAssertEqual(targets.size(), 1);
    XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
    XCTAssertFalse(targets[0].isReadable);
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_CLONE;
    esMsg.event.clone.source = &testFile1;
    esMsg.event.clone.target_dir = &testDir;
    esMsg.event.clone.target_name = testTok;

    std::vector<PathTarget> targets;
    PopulatePathTargets(msg, targets);

    XCTAssertEqual(targets.size(), 2);
    XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
    XCTAssertTrue(targets[0].isReadable);
    XCTAssertCppStringEqual(targets[1].path, dirTok);
    XCTAssertFalse(targets[1].isReadable);
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_EXCHANGEDATA;
    esMsg.event.exchangedata.file1 = &testFile1;
    esMsg.event.exchangedata.file2 = &testFile2;

    std::vector<PathTarget> targets;
    PopulatePathTargets(msg, targets);

    XCTAssertEqual(targets.size(), 2);
    XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
    XCTAssertFalse(targets[0].isReadable);
    XCTAssertCStringEqual(targets[1].path.c_str(), testFile2.path.data);
    XCTAssertFalse(targets[1].isReadable);
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_CREATE;
    esMsg.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
    esMsg.event.create.destination.new_path.dir = &testDir;
    esMsg.event.create.destination.new_path.filename = testTok;

    std::vector<PathTarget> targets;
    PopulatePathTargets(msg, targets);

    XCTAssertEqual(targets.size(), 1);
    XCTAssertCppStringEqual(targets[0].path, dirTok);
    XCTAssertFalse(targets[0].isReadable);
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_TRUNCATE;
    esMsg.event.truncate.target = &testFile1;

    std::vector<PathTarget> targets;
    PopulatePathTargets(msg, targets);

    XCTAssertEqual(targets.size(), 1);
    XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
    XCTAssertFalse(targets[0].isReadable);
  }

  if (@available(macOS 12.0, *)) {
    {
      esMsg.event_type = ES_EVENT_TYPE_AUTH_COPYFILE;
      esMsg.event.copyfile.source = &testFile1;
      esMsg.event.copyfile.target_dir = &testDir;
      esMsg.event.copyfile.target_name = testTok;

      {
        esMsg.event.copyfile.target_file = nullptr;

        std::vector<PathTarget> targets;
        PopulatePathTargets(msg, targets);

        XCTAssertEqual(targets.size(), 2);
        XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
        XCTAssertTrue(targets[0].isReadable);
        XCTAssertCppStringEqual(targets[1].path, dirTok);
        XCTAssertFalse(targets[1].isReadable);
      }

      {
        esMsg.event.copyfile.target_file = &testFile2;

        std::vector<PathTarget> targets;
        PopulatePathTargets(msg, targets);

        XCTAssertEqual(targets.size(), 2);
        XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
        XCTAssertTrue(targets[0].isReadable);
        XCTAssertCStringEqual(targets[1].path.c_str(), testFile2.path.data);
        XCTAssertFalse(targets[1].isReadable);
      }
    }
  }
}

@end
