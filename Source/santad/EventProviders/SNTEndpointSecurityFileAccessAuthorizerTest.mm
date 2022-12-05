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

#import "Source/santad/EventProviders/SNTEndpointSecurityFileAccessAuthorizer.h"

#include <EndpointSecurity/ESTypes.h>
#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <cstddef>
#include <variant>

#include "Source/common/SNTCachedDecision.h"
#include "Source/common/TestUtils.h"
#include "Source/common/Unit.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/SNTDecisionCache.h"

using santa::common::Unit;
using santa::santad::event_providers::endpoint_security::Message;

extern const char *kBadCertHash;

using PathTargets = std::pair<std::string_view, std::variant<std::string_view, std::string, Unit>>;
extern PathTargets GetPathTargets(const Message &msg);

extern es_auth_result_t CombinePolicyResults(es_auth_result_t result1, es_auth_result_t result2);

@interface SNTEndpointSecurityFileAccessAuthorizer (Testing)
- (NSString *)getCertificateHash:(es_file_t *)esFile;
@end

@interface SNTEndpointSecurityFileAccessAuthorizerTest : XCTestCase
@property id cscMock;
@property id dcMock;
@end

@implementation SNTEndpointSecurityFileAccessAuthorizerTest

- (void)setUp {
  [super setUp];

  self.cscMock = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([self.cscMock alloc]).andReturn(self.cscMock);

  self.dcMock = OCMStrictClassMock([SNTDecisionCache class]);
}

- (void)tearDown {
  [self.cscMock stopMocking];
  [self.dcMock stopMocking];

  [super tearDown];
}

- (void)testGetCertificateHashFailedCodesign {
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

  SNTEndpointSecurityFileAccessAuthorizer *accessClient =
    [[SNTEndpointSecurityFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                           metrics:nullptr
                                                            logger:nullptr
                                                        watchItems:nullptr
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
  want = @(kBadCertHash);

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

- (void)testEnable {
  std::set<es_event_type_t> expectedEventSubs{
    ES_EVENT_TYPE_AUTH_OPEN,   ES_EVENT_TYPE_AUTH_LINK,  ES_EVENT_TYPE_AUTH_RENAME,
    ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_AUTH_CLONE, ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
  };

#if defined(MAC_OS_VERSION_12_0) && MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_VERSION_12_0
  if (@available(macOS 12.0, *)) {
    expectedEventSubs.insert(ES_EVENT_TYPE_AUTH_COPYFILE);
  }
#endif

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  id fileAccessClient = [[SNTEndpointSecurityFileAccessAuthorizer alloc]
    initWithESAPI:mockESApi
          metrics:nullptr
        processor:santa::santad::Processor::kFileAccessAuthorizer];

  EXPECT_CALL(*mockESApi, ClearCache)
    .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
             .WillOnce(testing::Return(true)))
    .WillOnce(testing::Return(true));

  [fileAccessClient enable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testGetPathTargets {
  // This test ensures that the `GetPathTargets` functions returns the
  // expected combination of targets for each handled event variant
  es_file_t testFile1 = MakeESFile("test_file_1");
  es_file_t testFile2 = MakeESFile("test_file_2");
  es_file_t testDir = MakeESFile("test_dir");
  es_string_token_t testTok = MakeESStringToken("test_tok");
  std::string dirTok = std::string(testDir.path.data) + std::string(testTok.data);

  es_message_t esMsg;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  Message msg(mockESApi, &esMsg);

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_OPEN;
    esMsg.event.open.file = &testFile1;

    PathTargets targets = GetPathTargets(msg);

    XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
    XCTAssertTrue(std::holds_alternative<Unit>(targets.second));
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_LINK;
    esMsg.event.link.source = &testFile1;
    esMsg.event.link.target_dir = &testDir;
    esMsg.event.link.target_filename = testTok;

    PathTargets targets = GetPathTargets(msg);

    XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
    XCTAssertTrue(std::holds_alternative<std::string>(targets.second));
    XCTAssertCppStringEqual(std::get<std::string>(targets.second), dirTok);
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_RENAME;
    esMsg.event.rename.source = &testFile1;

    {
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
      esMsg.event.rename.destination.existing_file = &testFile2;

      PathTargets targets = GetPathTargets(msg);

      XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
      XCTAssertTrue(std::holds_alternative<std::string_view>(targets.second));
      XCTAssertCStringEqual(std::get<std::string_view>(targets.second).data(), testFile2.path.data);
    }

    {
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
      esMsg.event.rename.destination.new_path.dir = &testDir;
      esMsg.event.rename.destination.new_path.filename = testTok;

      PathTargets targets = GetPathTargets(msg);

      XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
      XCTAssertTrue(std::holds_alternative<std::string>(targets.second));
      XCTAssertCppStringEqual(std::get<std::string>(targets.second), dirTok);
    }
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_UNLINK;
    esMsg.event.unlink.target = &testFile1;

    PathTargets targets = GetPathTargets(msg);

    XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
    XCTAssertTrue(std::holds_alternative<Unit>(targets.second));
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_CLONE;
    esMsg.event.clone.source = &testFile1;
    esMsg.event.clone.target_dir = &testDir;
    esMsg.event.clone.target_name = testTok;

    PathTargets targets = GetPathTargets(msg);

    XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
    XCTAssertTrue(std::holds_alternative<std::string>(targets.second));
    XCTAssertCppStringEqual(std::get<std::string>(targets.second), dirTok);
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_EXCHANGEDATA;
    esMsg.event.exchangedata.file1 = &testFile1;
    esMsg.event.exchangedata.file2 = &testFile2;

    PathTargets targets = GetPathTargets(msg);

    XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
    XCTAssertTrue(std::holds_alternative<std::string_view>(targets.second));
    XCTAssertCStringEqual(std::get<std::string_view>(targets.second).data(), testFile2.path.data);
  }

  if (@available(macOS 12.0, *)) {
    {
      esMsg.event_type = ES_EVENT_TYPE_AUTH_COPYFILE;
      esMsg.event.copyfile.source = &testFile1;
      esMsg.event.copyfile.target_dir = &testDir;
      esMsg.event.copyfile.target_name = testTok;

      {
        esMsg.event.copyfile.target_file = nullptr;

        PathTargets targets = GetPathTargets(msg);

        XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
        XCTAssertTrue(std::holds_alternative<std::string>(targets.second));
        XCTAssertCppStringEqual(std::get<std::string>(targets.second), dirTok);
      }

      {
        esMsg.event.copyfile.target_file = &testFile2;

        PathTargets targets = GetPathTargets(msg);

        XCTAssertCStringEqual(targets.first.data(), testFile1.path.data);
        XCTAssertTrue(std::holds_alternative<std::string_view>(targets.second));
        XCTAssertCStringEqual(std::get<std::string_view>(targets.second).data(),
                              testFile2.path.data);
      }
    }
  }
}

@end
