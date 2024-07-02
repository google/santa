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

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <bsm/libbsm.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <map>
#include <string>

#include "Source/common/Platform.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredEvent.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#import "Source/santad/SNTDecisionCache.h"

using santa::santad::event_providers::endpoint_security::Enricher;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::serializers::BasicString;
using santa::santad::logs::endpoint_security::serializers::Serializer;

namespace santa::santad::logs::endpoint_security::serializers {
extern std::string GetDecisionString(SNTEventState event_state);
extern std::string GetReasonString(SNTEventState event_state);
extern std::string GetModeString(SNTClientMode mode);
extern std::string GetAccessTypeString(es_event_type_t event_type);
extern std::string GetFileAccessPolicyDecisionString(FileAccessPolicyDecision decision);
}  // namespace santa::santad::logs::endpoint_security::serializers

using santa::santad::logs::endpoint_security::serializers::GetAccessTypeString;
using santa::santad::logs::endpoint_security::serializers::GetDecisionString;
using santa::santad::logs::endpoint_security::serializers::GetFileAccessPolicyDecisionString;
using santa::santad::logs::endpoint_security::serializers::GetModeString;
using santa::santad::logs::endpoint_security::serializers::GetReasonString;

std::string BasicStringSerializeMessage(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                        es_message_t *esMsg, SNTDecisionCache *decisionCache) {
  mockESApi->SetExpectationsRetainReleaseMessage();

  std::shared_ptr<Serializer> bs = BasicString::Create(mockESApi, decisionCache, false);
  std::vector<uint8_t> ret = bs->SerializeMessage(Enricher().Enrich(Message(mockESApi, esMsg)));

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());

  return std::string(ret.begin(), ret.end());
}

std::string BasicStringSerializeMessage(es_message_t *esMsg) {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  return BasicStringSerializeMessage(mockESApi, esMsg, nil);
}

@interface BasicStringTest : XCTestCase
@property id mockConfigurator;
@property id mockDecisionCache;

@property SNTCachedDecision *testCachedDecision;
@end

@implementation BasicStringTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator enableMachineIDDecoration]).andReturn(YES);
  OCMStub([self.mockConfigurator machineID]).andReturn(@"my_id");

  self.testCachedDecision = [[SNTCachedDecision alloc] init];
  self.testCachedDecision.decision = SNTEventStateAllowBinary;
  self.testCachedDecision.decisionExtra = @"extra!";
  self.testCachedDecision.sha256 = @"1234_hash";
  self.testCachedDecision.quarantineURL = @"google.com";
  self.testCachedDecision.certSHA256 = @"5678_hash";
  self.testCachedDecision.decisionClientMode = SNTClientModeLockdown;

  self.mockDecisionCache = OCMClassMock([SNTDecisionCache class]);
  OCMStub([self.mockDecisionCache sharedCache]).andReturn(self.mockDecisionCache);
  OCMStub([self.mockDecisionCache resetTimestampForCachedDecision:{}])
    .ignoringNonObjectArgs()
    .andReturn(self.testCachedDecision);
}

- (void)tearDown {
  [self.mockConfigurator stopMocking];
  [self.mockDecisionCache stopMocking];
}

- (void)testSerializeMessageClose {
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_file_t file = MakeESFile("close_file");
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &proc);
  esMsg.event.close.modified = true;
  esMsg.event.close.target = &file;

  std::string got = BasicStringSerializeMessage(&esMsg);
  std::string want = "action=WRITE|path=close_file"
                     "|pid=12|ppid=56|process=foo|processpath=foo"
                     "|uid=-2|user=nobody|gid=-1|group=nogroup|machineid=my_id\n";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeMessageExchange {
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_file_t file1 = MakeESFile("exchange_1");
  es_file_t file2 = MakeESFile("exchange_2");
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, &proc);
  esMsg.event.exchangedata.file1 = &file1;
  esMsg.event.exchangedata.file2 = &file2;

  // Arbitrarily overwriting mock to test not adding machine id in this event
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator enableMachineIDDecoration]).andReturn(NO);

  std::string got = BasicStringSerializeMessage(&esMsg);
  std::string want = "action=EXCHANGE|path=exchange_1|newpath=exchange_2"
                     "|pid=12|ppid=56|process=foo|processpath=foo"
                     "|uid=-2|user=nobody|gid=-1|group=nogroup\n";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeMessageExec {
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));

  es_file_t execFile = MakeESFile("execpath|");
  es_process_t procExec = MakeESProcess(&execFile, MakeAuditToken(12, 89), MakeAuditToken(56, 78));

  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXEC, &proc);
  esMsg.event.exec.target = &procExec;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, ExecArgCount).WillOnce(testing::Return(3));

  EXPECT_CALL(*mockESApi, ExecArg)
    .WillOnce(testing::Return(es_string_token_t{9, "exec|path"}))
    .WillOnce(testing::Return(es_string_token_t{5, "-l\n-t"}))
    .WillOnce(testing::Return(es_string_token_t{8, "-v\r--foo"}));

  std::string got = BasicStringSerializeMessage(mockESApi, &esMsg, self.mockDecisionCache);
  std::string want =
    "action=EXEC|decision=ALLOW|reason=BINARY|explain=extra!|sha256=1234_hash|"
    "cert_sha256=5678_hash|cert_cn=|quarantine_url=google.com|pid=12|pidversion="
    "89|ppid=56|uid=-2|user=nobody|gid=-1|group=nogroup|mode=L|path=execpath<pipe>|"
    "args=exec<pipe>path -l\\n-t -v\\r--foo|machineid=my_id\n";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeMessageExit {
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);

  std::string got = BasicStringSerializeMessage(&esMsg);
  std::string want = "action=EXIT|pid=12|pidversion=34|ppid=56|uid=-2|gid=-1|machineid=my_id\n";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeMessageFork {
  es_file_t procFile = MakeESFile("foo");
  es_file_t procChildFile = MakeESFile("foo_child");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_process_t procChild =
    MakeESProcess(&procChildFile, MakeAuditToken(67, 89), MakeAuditToken(12, 34));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_FORK, &proc);
  esMsg.event.fork.child = &procChild;

  std::string got = BasicStringSerializeMessage(&esMsg);
  std::string want = "action=FORK|pid=67|pidversion=89|ppid=12|uid=-2|gid=-1|machineid=my_id\n";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeMessageLink {
  es_file_t procFile = MakeESFile("foo");
  es_file_t srcFile = MakeESFile("link_src");
  es_file_t dstDir = MakeESFile("link_dst");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_LINK, &proc);
  esMsg.event.link.source = &srcFile;
  esMsg.event.link.target_dir = &dstDir;
  esMsg.event.link.target_filename = MakeESStringToken("link_name");

  std::string got = BasicStringSerializeMessage(&esMsg);
  std::string want = "action=LINK|path=link_src|newpath=link_dst/link_name"
                     "|pid=12|ppid=56|process=foo|processpath=foo"
                     "|uid=-2|user=nobody|gid=-1|group=nogroup|machineid=my_id\n";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeMessageRename {
  es_file_t procFile = MakeESFile("foo");
  es_file_t srcFile = MakeESFile("rename_src");
  es_file_t dstFile = MakeESFile("rename_dst");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_RENAME, &proc);
  esMsg.event.rename.source = &srcFile;
  esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
  esMsg.event.rename.destination.existing_file = &dstFile;

  std::string got = BasicStringSerializeMessage(&esMsg);
  std::string want = "action=RENAME|path=rename_src|newpath=rename_dst"
                     "|pid=12|ppid=56|process=foo|processpath=foo"
                     "|uid=-2|user=nobody|gid=-1|group=nogroup|machineid=my_id\n";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeMessageUnlink {
  es_file_t procFile = MakeESFile("foo");
  es_file_t targetFile = MakeESFile("deleted_file");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_UNLINK, &proc);
  esMsg.event.unlink.target = &targetFile;

  std::string got = BasicStringSerializeMessage(&esMsg);
  std::string want = "action=DELETE|path=deleted_file"
                     "|pid=12|ppid=56|process=foo|processpath=foo"
                     "|uid=-2|user=nobody|gid=-1|group=nogroup|machineid=my_id\n";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeMessageCSInvalidated {
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED, &proc);

  std::string got = BasicStringSerializeMessage(&esMsg);
  std::string want =
    "action=CODESIGNING_INVALIDATED"
    "|pid=12|ppid=56|process=foo|processpath=foo"
    "|uid=-2|user=nobody|gid=-1|group=nogroup|codesigning_flags=0x00000000|machineid=my_id\n";

  XCTAssertCppStringEqual(got, want);
}

- (void)testGetAccessTypeString {
  std::map<es_event_type_t, std::string> accessTypeToString = {
    {ES_EVENT_TYPE_AUTH_OPEN, "OPEN"},         {ES_EVENT_TYPE_AUTH_LINK, "LINK"},
    {ES_EVENT_TYPE_AUTH_RENAME, "RENAME"},     {ES_EVENT_TYPE_AUTH_UNLINK, "UNLINK"},
    {ES_EVENT_TYPE_AUTH_CLONE, "CLONE"},       {ES_EVENT_TYPE_AUTH_EXCHANGEDATA, "EXCHANGEDATA"},
    {ES_EVENT_TYPE_AUTH_CREATE, "CREATE"},     {ES_EVENT_TYPE_AUTH_TRUNCATE, "TRUNCATE"},
    {ES_EVENT_TYPE_AUTH_COPYFILE, "COPYFILE"}, {(es_event_type_t)1234, "UNKNOWN_TYPE_1234"},
  };

  for (const auto &kv : accessTypeToString) {
    XCTAssertCppStringEqual(GetAccessTypeString(kv.first), kv.second);
  }
}

- (void)testGetFileAccessPolicyDecisionString {
  std::map<FileAccessPolicyDecision, std::string> policyDecisionToString = {
    {FileAccessPolicyDecision::kNoPolicy, "NO_POLICY"},
    {FileAccessPolicyDecision::kDenied, "DENIED"},
    {FileAccessPolicyDecision::kDeniedInvalidSignature, "DENIED_INVALID_SIGNATURE"},
    {FileAccessPolicyDecision::kAllowed, "ALLOWED"},
    {FileAccessPolicyDecision::kAllowedReadAccess, "ALLOWED_READ_ACCESS"},
    {FileAccessPolicyDecision::kAllowedAuditOnly, "AUDIT_ONLY"},
    {(FileAccessPolicyDecision)1234, "UNKNOWN_DECISION_1234"},
  };

  for (const auto &kv : policyDecisionToString) {
    XCTAssertCppStringEqual(GetFileAccessPolicyDecisionString(kv.first), kv.second);
  }
}

- (void)testSerializeFileAccess {
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_OPEN, &proc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  std::vector<uint8_t> ret =
    BasicString::Create(nullptr, nil, false)
      ->SerializeFileAccess("v1.0", "pol_name", Message(mockESApi, &esMsg),
                            Enricher().Enrich(*esMsg.process), "file_target",
                            FileAccessPolicyDecision::kAllowedAuditOnly);
  std::string got(ret.begin(), ret.end());
  std::string want =
    "action=FILE_ACCESS|policy_version=v1.0|policy_name=pol_name|path=file_target|access_type=OPEN|"
    "decision=AUDIT_ONLY|pid=12|ppid=56|"
    "process=foo|processpath=foo|uid=-2|user=nobody|gid=-1|group=nogroup|machineid=my_id\n";
  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeAllowlist {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &proc);
  esMsg.event.close.target = &file;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  std::vector<uint8_t> ret = BasicString::Create(mockESApi, nil, false)
                               ->SerializeAllowlist(Message(mockESApi, &esMsg), "test_hash");

  XCTAssertTrue(testing::Mock::VerifyAndClearExpectations(mockESApi.get()),
                "Expected calls were not properly mocked");

  std::string got(ret.begin(), ret.end());
  std::string want = "action=ALLOWLIST|pid=12|pidversion=34|path=foo"
                     "|sha256=test_hash|machineid=my_id\n";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeBundleHashingEvent {
  SNTStoredEvent *se = [[SNTStoredEvent alloc] init];

  se.fileSHA256 = @"file_hash";
  se.fileBundleHash = @"file_bundle_hash";
  se.fileBundleName = @"file_bundle_Name";
  se.fileBundleID = nil;
  se.fileBundlePath = @"file_bundle_path";
  se.filePath = @"file_path";

  std::vector<uint8_t> ret =
    BasicString::Create(nullptr, nil, false)->SerializeBundleHashingEvent(se);
  std::string got(ret.begin(), ret.end());

  std::string want = "action=BUNDLE|sha256=file_hash"
                     "|bundlehash=file_bundle_hash|bundlename=file_bundle_Name|bundleid="
                     "|bundlepath=file_bundle_path|path=file_path|machineid=my_id\n";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeDiskAppeared {
  NSDictionary *props = @{
    @"DADevicePath" : @"",
    @"DADeviceVendor" : @"vendor",
    @"DADeviceModel" : @"model",
    @"DAAppearanceTime" : @(1252487349),  // 2009-09-09 09:09:09
    @"DAVolumePath" : [NSURL URLWithString:@"/"],
    @"DAMediaBSDName" : @"bsd",
    @"DAVolumeKind" : @"apfs",
    @"DADeviceProtocol" : @"usb",
  };

  // Arbitrarily overwriting mock to test not adding machine id in this event
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator enableMachineIDDecoration]).andReturn(NO);

  std::vector<uint8_t> ret = BasicString::Create(nullptr, nil, false)->SerializeDiskAppeared(props);
  std::string got(ret.begin(), ret.end());

  std::string want = "action=DISKAPPEAR|mount=/|volume=|bsdname=bsd|fs=apfs"
                     "|model=vendor model|serial=|bus=usb|dmgpath="
                     "|appearance=2040-09-09T09:09:09.000Z|mountfrom=/";

  XCTAssertCppStringBeginsWith(got, want);
}

- (void)testSerializeDiskDisappeared {
  NSDictionary *props = @{
    @"DAVolumePath" : [NSURL URLWithString:@"path"],
    @"DAMediaBSDName" : @"bsd",
  };

  std::vector<uint8_t> ret =
    BasicString::Create(nullptr, nil, false)->SerializeDiskDisappeared(props);
  std::string got(ret.begin(), ret.end());

  std::string want = "action=DISKDISAPPEAR|mount=path|volume=|bsdname=bsd|machineid=my_id\n";

  XCTAssertCppStringEqual(got, want);
}

- (void)testGetDecisionString {
  std::map<SNTEventState, std::string> stateToDecision = {
    {SNTEventStateUnknown, "UNKNOWN"},
    {SNTEventStateBundleBinary, "UNKNOWN"},
    {SNTEventStateBlockUnknown, "DENY"},
    {SNTEventStateBlockBinary, "DENY"},
    {SNTEventStateBlockCertificate, "DENY"},
    {SNTEventStateBlockScope, "DENY"},
    {SNTEventStateBlockTeamID, "DENY"},
    {SNTEventStateBlockLongPath, "DENY"},
    {SNTEventStateAllowUnknown, "ALLOW"},
    {SNTEventStateAllowBinary, "ALLOW"},
    {SNTEventStateAllowCertificate, "ALLOW"},
    {SNTEventStateAllowScope, "ALLOW"},
    {SNTEventStateAllowCompiler, "ALLOW"},
    {SNTEventStateAllowTransitive, "ALLOW"},
    {SNTEventStateAllowPendingTransitive, "ALLOW"},
    {SNTEventStateAllowTeamID, "ALLOW"},
  };

  for (const auto &kv : stateToDecision) {
    XCTAssertCppStringEqual(GetDecisionString(kv.first), kv.second);
  }
}

- (void)testGetReasonString {
  std::map<SNTEventState, std::string> stateToReason = {
    {SNTEventStateUnknown, "NOTRUNNING"},
    {SNTEventStateBundleBinary, "NOTRUNNING"},
    {SNTEventStateBlockUnknown, "UNKNOWN"},
    {SNTEventStateBlockBinary, "BINARY"},
    {SNTEventStateBlockCertificate, "CERT"},
    {SNTEventStateBlockScope, "SCOPE"},
    {SNTEventStateBlockTeamID, "TEAMID"},
    {SNTEventStateBlockSigningID, "SIGNINGID"},
    {SNTEventStateBlockCDHash, "CDHASH"},
    {SNTEventStateBlockLongPath, "LONG_PATH"},
    {SNTEventStateAllowUnknown, "UNKNOWN"},
    {SNTEventStateAllowBinary, "BINARY"},
    {SNTEventStateAllowCertificate, "CERT"},
    {SNTEventStateAllowScope, "SCOPE"},
    {SNTEventStateAllowCompiler, "COMPILER"},
    {SNTEventStateAllowTransitive, "TRANSITIVE"},
    {SNTEventStateAllowPendingTransitive, "PENDING_TRANSITIVE"},
    {SNTEventStateAllowTeamID, "TEAMID"},
    {SNTEventStateAllowSigningID, "SIGNINGID"},
    {SNTEventStateAllowCDHash, "CDHASH"},
  };

  for (const auto &kv : stateToReason) {
    XCTAssertCppStringEqual(GetReasonString(kv.first), kv.second);
  }
}

- (void)testGetModeString {
  std::map<SNTClientMode, std::string> modeToString = {
    {SNTClientModeMonitor, "M"},
    {SNTClientModeLockdown, "L"},
    {(SNTClientMode)123, "U"},
  };

  for (const auto &kv : modeToString) {
    XCTAssertCppStringEqual(GetModeString(kv.first), kv.second);
  }
}

@end
