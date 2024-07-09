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
#include <sys/types.h>
#include <cstring>
#include <utility>

#include <array>
#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <variant>

#include "Source/common/Platform.h"
#include "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/DataLayer/WatchItems.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityFileAccessAuthorizer.h"
#include "Source/santad/Logs/EndpointSecurity/MockLogger.h"
#include "Source/santad/SNTDecisionCache.h"

using santa::Message;
using santa::WatchItemPolicy;

extern NSString *kBadCertHash;

// Duplicate definition for test implementation
struct PathTarget {
  std::string path;
  bool isReadable;
  std::optional<std::pair<dev_t, ino_t>> devnoIno;
};

using PathTargetsPair = std::pair<std::optional<std::string>, std::optional<std::string>>;
extern void PopulatePathTargets(const Message &msg, std::vector<PathTarget> &targets);
extern es_auth_result_t FileAccessPolicyDecisionToESAuthResult(FileAccessPolicyDecision decision);
extern bool ShouldLogDecision(FileAccessPolicyDecision decision);
extern bool ShouldNotifyUserDecision(FileAccessPolicyDecision decision);
extern es_auth_result_t CombinePolicyResults(es_auth_result_t result1, es_auth_result_t result2);
extern bool IsBlockDecision(FileAccessPolicyDecision decision);
extern FileAccessPolicyDecision ApplyOverrideToDecision(FileAccessPolicyDecision decision,
                                                        SNTOverrideFileAccessAction overrideAction);

static inline std::pair<dev_t, ino_t> FileID(const es_file_t &file) {
  return std::make_pair(file.stat.st_dev, file.stat.st_ino);
}

void SetExpectationsForFileAccessAuthorizerInit(
  std::shared_ptr<MockEndpointSecurityAPI> mockESApi) {
  EXPECT_CALL(*mockESApi, InvertTargetPathMuting).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, UnmuteAllTargetPaths).WillOnce(testing::Return(true));
}

// Helper to reset a policy to an empty state
void ClearWatchItemPolicyProcess(WatchItemPolicy::Process &proc) {
  proc.binary_path = "";
  proc.signing_id = "";
  proc.team_id = "";
  proc.certificate_sha256 = "";
  proc.cdhash.clear();
}

@interface SNTEndpointSecurityFileAccessAuthorizer (Testing)
- (NSString *)getCertificateHash:(es_file_t *)esFile;
- (FileAccessPolicyDecision)specialCaseForPolicy:(std::shared_ptr<WatchItemPolicy>)policy
                                          target:(const PathTarget &)target
                                         message:(const Message &)msg;
- (bool)policyProcess:(const WatchItemPolicy::Process &)policyProc
     matchesESProcess:(const es_process_t *)esProc;
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
                                                     decisionCache:self.dcMock
                                                         ttyWriter:nullptr];

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
    {(FileAccessPolicyDecision)123, false},
  };

  for (const auto &kv : policyDecisionToShouldLog) {
    XCTAssertEqual(ShouldLogDecision(kv.first), kv.second);
  }
}

- (void)testShouldNotifyUserDecision {
  std::map<FileAccessPolicyDecision, bool> policyDecisionToShouldLog = {
    {FileAccessPolicyDecision::kNoPolicy, false},
    {FileAccessPolicyDecision::kDenied, true},
    {FileAccessPolicyDecision::kDeniedInvalidSignature, true},
    {FileAccessPolicyDecision::kAllowed, false},
    {FileAccessPolicyDecision::kAllowedReadAccess, false},
    {FileAccessPolicyDecision::kAllowedAuditOnly, false},
    {(FileAccessPolicyDecision)123, false},
  };

  for (const auto &kv : policyDecisionToShouldLog) {
    XCTAssertEqual(ShouldNotifyUserDecision(kv.first), kv.second);
  }
}

- (void)testIsBlockDecision {
  std::map<FileAccessPolicyDecision, bool> policyDecisionToIsBlockDecision = {
    {FileAccessPolicyDecision::kNoPolicy, false},
    {FileAccessPolicyDecision::kDenied, true},
    {FileAccessPolicyDecision::kDeniedInvalidSignature, true},
    {FileAccessPolicyDecision::kAllowed, false},
    {FileAccessPolicyDecision::kAllowedReadAccess, false},
    {FileAccessPolicyDecision::kAllowedAuditOnly, false},
    {(FileAccessPolicyDecision)123, false},
  };

  for (const auto &kv : policyDecisionToIsBlockDecision) {
    XCTAssertEqual(ShouldNotifyUserDecision(kv.first), kv.second);
  }
}

- (void)testApplyOverrideToDecision {
  std::map<std::pair<FileAccessPolicyDecision, SNTOverrideFileAccessAction>,
           FileAccessPolicyDecision>
    decisionAndOverrideToDecision = {
      // Override action: None - Policy shouldn't be changed
      {{FileAccessPolicyDecision::kNoPolicy, SNTOverrideFileAccessActionNone},
       FileAccessPolicyDecision::kNoPolicy},
      {{FileAccessPolicyDecision::kDenied, SNTOverrideFileAccessActionNone},
       FileAccessPolicyDecision::kDenied},

      // Override action: AuditOnly - Policy should be changed only on blocked decisions
      {{FileAccessPolicyDecision::kNoPolicy, SNTOverrideFileAccessActionAuditOnly},
       FileAccessPolicyDecision::kNoPolicy},
      {{FileAccessPolicyDecision::kAllowedAuditOnly, SNTOverrideFileAccessActionAuditOnly},
       FileAccessPolicyDecision::kAllowedAuditOnly},
      {{FileAccessPolicyDecision::kAllowedReadAccess, SNTOverrideFileAccessActionAuditOnly},
       FileAccessPolicyDecision::kAllowedReadAccess},
      {{FileAccessPolicyDecision::kDenied, SNTOverrideFileAccessActionAuditOnly},
       FileAccessPolicyDecision::kAllowedAuditOnly},
      {{FileAccessPolicyDecision::kDeniedInvalidSignature, SNTOverrideFileAccessActionAuditOnly},
       FileAccessPolicyDecision::kAllowedAuditOnly},

      // Override action: Disable - Always changes the decision to be no policy applied
      {{FileAccessPolicyDecision::kAllowed, SNTOverrideFileAccessActionDiable},
       FileAccessPolicyDecision::kNoPolicy},
      {{FileAccessPolicyDecision::kDenied, SNTOverrideFileAccessActionDiable},
       FileAccessPolicyDecision::kNoPolicy},
      {{FileAccessPolicyDecision::kAllowedReadAccess, SNTOverrideFileAccessActionDiable},
       FileAccessPolicyDecision::kNoPolicy},
      {{FileAccessPolicyDecision::kAllowedAuditOnly, SNTOverrideFileAccessActionDiable},
       FileAccessPolicyDecision::kNoPolicy},
  };

  for (const auto &kv : decisionAndOverrideToDecision) {
    XCTAssertEqual(ApplyOverrideToDecision(kv.first.first, kv.first.second), kv.second);
  }

  XCTAssertThrows(
    ApplyOverrideToDecision(FileAccessPolicyDecision::kAllowed, (SNTOverrideFileAccessAction)123));
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
                                                     decisionCache:nil
                                                         ttyWriter:nullptr];

  auto policy = std::make_shared<WatchItemPolicy>("foo_policy", "/foo");

  FileAccessPolicyDecision result;
  PathTarget target = {.path = "/some/random/path", .isReadable = true};

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_OPEN;

    // Write-only policy, Write operation
    {
      policy->allow_read_access = true;
      esMsg.event.open.fflag = FWRITE | FREAD;
      Message msg(mockESApi, &esMsg);
      result = [accessClient specialCaseForPolicy:policy target:target message:msg];
      XCTAssertEqual(result, FileAccessPolicyDecision::kNoPolicy);
    }

    // Write-only policy, Read operation
    {
      policy->allow_read_access = true;
      esMsg.event.open.fflag = FREAD;
      Message msg(mockESApi, &esMsg);
      result = [accessClient specialCaseForPolicy:policy target:target message:msg];
      XCTAssertEqual(result, FileAccessPolicyDecision::kAllowedReadAccess);
    }

    // Read/Write policy, Read operation
    {
      policy->allow_read_access = false;
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
      policy->allow_read_access = true;
      target.isReadable = true;
      Message msg(mockESApi, &esMsg);
      result = [accessClient specialCaseForPolicy:policy target:target message:msg];
      XCTAssertEqual(result, FileAccessPolicyDecision::kAllowedReadAccess);
    }

    // Write-only policy, target not readable
    {
      policy->allow_read_access = true;
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
      policy->allow_read_access = true;
      target.isReadable = true;
      Message msg(mockESApi, &esMsg);
      result = [accessClient specialCaseForPolicy:policy target:target message:msg];
      XCTAssertEqual(result, FileAccessPolicyDecision::kAllowedReadAccess);
    }

    // Write-only policy, target not readable
    {
      policy->allow_read_access = true;
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

- (void)testPolicyProcessMatchesESProcess {
  const char *instigatingCertHash = "abc123";
  const char *teamId = "myvalidtid";
  const char *signingId = "com.google.test";
  std::vector<uint8_t> cdhashBytes(CS_CDHASH_LEN);
  std::fill(cdhashBytes.begin(), cdhashBytes.end(), 0xAA);
  es_file_t esFile = MakeESFile("foo");
  es_process_t esProc = MakeESProcess(&esFile);
  esProc.codesigning_flags = CS_SIGNED;
  esProc.team_id = MakeESStringToken(teamId);
  esProc.signing_id = MakeESStringToken(signingId);
  esProc.is_platform_binary = true;
  std::memcpy(esProc.cdhash, cdhashBytes.data(), sizeof(esProc.cdhash));

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
                                                     decisionCache:nil
                                                         ttyWriter:nullptr];

  id accessClientMock = OCMPartialMock(accessClient);

  OCMStub([accessClientMock getCertificateHash:&esFile])
    .ignoringNonObjectArgs()
    .andReturn(@(instigatingCertHash));

  WatchItemPolicy::Process policyProc("", "", "", {}, "", std::nullopt);

  {
    // Process policy matching single attribute - path
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.binary_path = "foo";
    XCTAssertTrue([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
    policyProc.binary_path = "badpath";
    XCTAssertFalse([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
  }

  {
    // Process policy matching single attribute - SigningID
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.signing_id = signingId;
    XCTAssertTrue([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
    policyProc.signing_id = "badid";
    XCTAssertFalse([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
    es_process_t esProcEmptySigningID = MakeESProcess(&esFile);
    esProcEmptySigningID.codesigning_flags = CS_SIGNED;
    esProcEmptySigningID.team_id.data = NULL;
    esProcEmptySigningID.team_id.length = 0;
    XCTAssertFalse([accessClient policyProcess:policyProc matchesESProcess:&esProcEmptySigningID]);
  }

  {
    // Process policy matching single attribute - TeamID
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.team_id = teamId;
    XCTAssertTrue([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
    policyProc.team_id = "badid";
    XCTAssertFalse([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
    es_process_t esProcEmptyTeamID = MakeESProcess(&esFile);
    esProcEmptyTeamID.codesigning_flags = CS_SIGNED;
    esProcEmptyTeamID.signing_id.data = NULL;
    esProcEmptyTeamID.signing_id.length = 0;
    XCTAssertFalse([accessClient policyProcess:policyProc matchesESProcess:&esProcEmptyTeamID]);
  }

  {
    // Process policy matching single attribute - cert hash
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.certificate_sha256 = instigatingCertHash;
    XCTAssertTrue([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
    policyProc.certificate_sha256 = "badcert";
    XCTAssertFalse([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
  }

  {
    // Process policy matching single attribute - cdhash
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.cdhash = cdhashBytes;
    XCTAssertTrue([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
    policyProc.cdhash[0] = 0x0;
    XCTAssertFalse([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
  }

  {
    // Process policy matching single attribute - platform binary
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.platform_binary = std::make_optional(true);
    XCTAssertTrue([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
    policyProc.platform_binary = std::make_optional(false);
    XCTAssertFalse([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
  }

  {
    // Process policy with only a subset of matching attributes
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.binary_path = "foo";
    policyProc.team_id = "invalidtid";
    XCTAssertFalse([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
  }

  {
    // Process policy with codesigning-based attributes, but unsigned ES process
    ClearWatchItemPolicyProcess(policyProc);
    esProc.codesigning_flags = 0x0;
    policyProc.team_id = "myvalidtid";
    XCTAssertFalse([accessClient policyProcess:policyProc matchesESProcess:&esProc]);
  }

  [accessClientMock stopMocking];
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testApplyPolicyToMessage {
  const char *instigatingPath = "/path/to/proc";
  const char *instigatingTeamID = "my_teamid";
  const char *instigatingCertHash = "abc123";
  WatchItemPolicy::Process policyProc(instigatingPath, "", "", {}, "", std::nullopt);
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
                                                     decisionCache:nil
                                                         ttyWriter:nullptr];

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
    XCTAssertEqual([accessClient applyPolicy:std::nullopt
                                   forTarget:target
                                   toMessage:Message(mockESApi, &esMsg)],
                   FileAccessPolicyDecision::kNoPolicy);
  }

  auto policy = std::make_shared<WatchItemPolicy>("foo_policy", "/foo");
  policy->processes.push_back(policyProc);
  auto optionalPolicy = std::make_optional<std::shared_ptr<WatchItemPolicy>>(policy);

  // Signed but invalid instigating processes are automatically
  // denied when `EnableBadSignatureProtection` is true
  {
    OCMExpect([self.mockConfigurator enableBadSignatureProtection]).andReturn(YES);
    esMsg.process->codesigning_flags = CS_SIGNED;
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy
                                   forTarget:target
                                   toMessage:Message(mockESApi, &esMsg)],
                   FileAccessPolicyDecision::kDeniedInvalidSignature);
  }

  // Signed but invalid instigating processes are not automatically
  // denied when `EnableBadSignatureProtection` is false. Policy
  // evaluation should continue normally.
  {
    OCMExpect([self.mockConfigurator enableBadSignatureProtection]).andReturn(NO);
    esMsg.process->codesigning_flags = CS_SIGNED;
    OCMExpect([accessClientMock policyProcess:policyProc matchesESProcess:&esProc])
      .ignoringNonObjectArgs()
      .andReturn(true);
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy
                                   forTarget:target
                                   toMessage:Message(mockESApi, &esMsg)],
                   FileAccessPolicyDecision::kAllowed);
  }

  // Set the codesign flags to be signed and valid for the remaining tests
  esMsg.process->codesigning_flags = CS_SIGNED | CS_VALID;

  // If no exceptions, operations are logged and denied
  {
    OCMExpect([accessClientMock policyProcess:policyProc matchesESProcess:&esProc])
      .ignoringNonObjectArgs()
      .andReturn(false);
    policy->audit_only = false;
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy
                                   forTarget:target
                                   toMessage:Message(mockESApi, &esMsg)],
                   FileAccessPolicyDecision::kDenied);
  }

  // For audit only policies with no exceptions, operations are logged but allowed
  {
    OCMExpect([accessClientMock policyProcess:policyProc matchesESProcess:&esProc])
      .ignoringNonObjectArgs()
      .andReturn(false);
    policy->audit_only = true;
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy
                                   forTarget:target
                                   toMessage:Message(mockESApi, &esMsg)],
                   FileAccessPolicyDecision::kAllowedAuditOnly);
  }

  // The remainder of the tests set the policy's `invert_process_exceptions` option
  policy->invert_process_exceptions = true;

  // If no exceptions for inverted policy, operations are allowed
  {
    OCMExpect([accessClientMock policyProcess:policyProc matchesESProcess:&esProc])
      .ignoringNonObjectArgs()
      .andReturn(false);
    policy->audit_only = false;
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy
                                   forTarget:target
                                   toMessage:Message(mockESApi, &esMsg)],
                   FileAccessPolicyDecision::kAllowed);
  }

  // For audit only policies with no exception matches and inverted exceptions, operations are
  // allowed
  {
    OCMExpect([accessClientMock policyProcess:policyProc matchesESProcess:&esProc])
      .ignoringNonObjectArgs()
      .andReturn(false);
    policy->audit_only = true;
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy
                                   forTarget:target
                                   toMessage:Message(mockESApi, &esMsg)],
                   FileAccessPolicyDecision::kAllowed);
  }

  // For audit only policies with exception match and inverted exceptions, operations are allowed
  // audit only
  {
    OCMExpect([accessClientMock policyProcess:policyProc matchesESProcess:&esProc])
      .ignoringNonObjectArgs()
      .andReturn(true);
    policy->audit_only = true;
    XCTAssertEqual([accessClient applyPolicy:optionalPolicy
                                   forTarget:target
                                   toMessage:Message(mockESApi, &esMsg)],
                   FileAccessPolicyDecision::kAllowedAuditOnly);
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testEnable {
  std::set<es_event_type_t> expectedEventSubs = {
    ES_EVENT_TYPE_AUTH_CLONE,        ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_AUTH_CREATE,
    ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_LINK,     ES_EVENT_TYPE_AUTH_OPEN,
    ES_EVENT_TYPE_AUTH_RENAME,       ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_UNLINK,
    ES_EVENT_TYPE_NOTIFY_EXIT,
  };

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, ClearCache)
    .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
             .WillOnce(testing::Return(true)))
    .WillOnce(testing::Return(true));

  id fileAccessClient = [[SNTEndpointSecurityFileAccessAuthorizer alloc]
    initWithESAPI:mockESApi
          metrics:nullptr
        processor:santa::Processor::kFileAccessAuthorizer];

  [fileAccessClient enable];

  for (const auto &event : expectedEventSubs) {
    XCTAssertNoThrow(santa::EventTypeToString(event));
  }

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
                                                     decisionCache:nil
                                                         ttyWriter:nullptr];

  EXPECT_CALL(*mockESApi, UnsubscribeAll);
  EXPECT_CALL(*mockESApi, UnmuteAllTargetPaths).WillOnce(testing::Return(true));

  accessClient.isSubscribed = true;
  [accessClient disable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testPopulatePathTargets {
  // This test ensures that the `GetPathTargets` functions returns the
  // expected combination of targets for each handled event variant
  es_file_t testFile1 = MakeESFile("test_file_1", MakeStat(100));
  es_file_t testFile2 = MakeESFile("test_file_2", MakeStat(200));
  es_file_t testDir = MakeESFile("test_dir", MakeStat(300));
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
    XCTAssertEqual(targets[0].devnoIno.value(), FileID(testFile1));
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
    XCTAssertFalse(targets[0].devnoIno.has_value());
    XCTAssertCppStringEqual(targets[1].path, dirTok);
    XCTAssertFalse(targets[1].isReadable);
    XCTAssertFalse(targets[1].devnoIno.has_value());
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
      XCTAssertFalse(targets[0].devnoIno.has_value());
      XCTAssertCStringEqual(targets[1].path.c_str(), testFile2.path.data);
      XCTAssertFalse(targets[1].isReadable);
      XCTAssertFalse(targets[1].devnoIno.has_value());
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
      XCTAssertFalse(targets[0].devnoIno.has_value());
      XCTAssertCppStringEqual(targets[1].path, dirTok);
      XCTAssertFalse(targets[1].isReadable);
      XCTAssertFalse(targets[1].devnoIno.has_value());
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
    XCTAssertFalse(targets[0].devnoIno.has_value());
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
    XCTAssertEqual(targets[0].devnoIno.value(), FileID(testFile1));
    XCTAssertCppStringEqual(targets[1].path, dirTok);
    XCTAssertFalse(targets[1].isReadable);
    XCTAssertFalse(targets[1].devnoIno.has_value());
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
    XCTAssertFalse(targets[0].devnoIno.has_value());
    XCTAssertCStringEqual(targets[1].path.c_str(), testFile2.path.data);
    XCTAssertFalse(targets[1].isReadable);
    XCTAssertFalse(targets[1].devnoIno.has_value());
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
    XCTAssertFalse(targets[0].devnoIno.has_value());
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_TRUNCATE;
    esMsg.event.truncate.target = &testFile1;

    std::vector<PathTarget> targets;
    PopulatePathTargets(msg, targets);

    XCTAssertEqual(targets.size(), 1);
    XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
    XCTAssertFalse(targets[0].isReadable);
    XCTAssertFalse(targets[0].devnoIno.has_value());
  }

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
      XCTAssertEqual(targets[0].devnoIno.value(), FileID(testFile1));
      XCTAssertCppStringEqual(targets[1].path, dirTok);
      XCTAssertFalse(targets[1].isReadable);
      XCTAssertFalse(targets[1].devnoIno.has_value());
    }

    {
      esMsg.event.copyfile.target_file = &testFile2;

      std::vector<PathTarget> targets;
      PopulatePathTargets(msg, targets);

      XCTAssertEqual(targets.size(), 2);
      XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
      XCTAssertTrue(targets[0].isReadable);
      XCTAssertEqual(targets[0].devnoIno.value(), FileID(testFile1));
      XCTAssertCStringEqual(targets[1].path.c_str(), testFile2.path.data);
      XCTAssertFalse(targets[1].isReadable);
      XCTAssertFalse(targets[1].devnoIno.has_value());
    }
  }
}

@end
