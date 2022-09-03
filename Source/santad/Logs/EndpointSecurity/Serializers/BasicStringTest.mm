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

#include <EndpointSecurity/ESTypes.h>
#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <bsm/libbsm.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <map>
#include <string>

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
}  // namespace santa::santad::logs::endpoint_security::serializers

using santa::santad::logs::endpoint_security::serializers::GetDecisionString;
using santa::santad::logs::endpoint_security::serializers::GetModeString;
using santa::santad::logs::endpoint_security::serializers::GetReasonString;

std::string BasicStringSerializeMessage(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                        es_message_t *esMsg) {
  mockESApi->SetExpectationsRetainReleaseMessage(esMsg);

  std::shared_ptr<Serializer> bs = BasicString::Create(mockESApi, false);
  auto ret = bs->SerializeMessage(Enricher().Enrich(Message(mockESApi, esMsg)));

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());

  return std::string(ret.begin(), ret.end());
}

std::string BasicStringSerializeMessage(es_message_t *esMsg) {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  return BasicStringSerializeMessage(mockESApi, esMsg);
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

  self.mockDecisionCache = OCMClassMock([SNTDecisionCache class]);
  OCMStub([self.mockDecisionCache sharedCache]).andReturn(self.mockDecisionCache);
  OCMStub([self.mockDecisionCache cachedDecisionForFile:{}])
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
                     "|uid=-2|user=nobody|gid=-2|group=nobody";

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

  std::string got = BasicStringSerializeMessage(&esMsg);
  std::string want = "action=EXCHANGE|path=exchange_1|newpath=exchange_2"
                     "|pid=12|ppid=56|process=foo|processpath=foo"
                     "|uid=-2|user=nobody|gid=-2|group=nobody";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeMessageExec {
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));

  es_file_t exec_file = MakeESFile("execpath");
  es_process_t proc_exec =
    MakeESProcess(&exec_file, MakeAuditToken(12, 89), MakeAuditToken(56, 78));

  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXEC, &proc);
  esMsg.event.exec.target = &proc_exec;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, ExecArgCount).WillOnce(testing::Return(3));

  EXPECT_CALL(*mockESApi, ExecArg)
    .WillOnce(testing::Return(es_string_token_t{8, "execpath"}))
    .WillOnce(testing::Return(es_string_token_t{2, "-l"}))
    .WillOnce(testing::Return(es_string_token_t{2, "-v"}));

  std::string got = BasicStringSerializeMessage(mockESApi, &esMsg);
  std::string want = "action=EXEC|decision=ALLOW|reason=BINARY|explain=extra!"
                     "|sha256=1234_hash|cert_sha256=5678_hash|cert_cn="
                     "|quarantine_url=google.com|pid=12|pidversion=89|ppid=56"
                     "|uid=-2|user=nobody|gid=-2|group=nobody"
                     "|mode=L|path=execpath|args=execpath -l -v|machineid=my_id";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeMessageExit {
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);

  std::string got = BasicStringSerializeMessage(&esMsg);
  std::string want = "action=EXIT|pid=12|pidversion=34|ppid=56|uid=-2|gid=-2";

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
  std::string want = "action=FORK|pid=67|pidversion=89|ppid=12|uid=-2|gid=-2";

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
                     "|uid=-2|user=nobody|gid=-2|group=nobody";

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
                     "|uid=-2|user=nobody|gid=-2|group=nobody";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeMessageUnlink {
  es_file_t procFile = MakeESFile("foo");
  es_file_t target_file = MakeESFile("deleted_file");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_UNLINK, &proc);
  esMsg.event.unlink.target = &target_file;

  std::string got = BasicStringSerializeMessage(&esMsg);
  std::string want = "action=DELETE|path=deleted_file"
                     "|pid=12|ppid=56|process=foo|processpath=foo"
                     "|uid=-2|user=nobody|gid=-2|group=nobody";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeAllowlist {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &proc);
  esMsg.event.close.target = &file;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage(&esMsg);

  auto ret = BasicString::Create(mockESApi, false)
               ->SerializeAllowlist(Message(mockESApi, &esMsg), "test_hash");

  XCTAssertTrue(testing::Mock::VerifyAndClearExpectations(mockESApi.get()),
                "Expected calls were not properly mocked");

  std::string got(ret.begin(), ret.end());
  std::string want = "action=ALLOWLIST|pid=12|pidversion=34|path=foo"
                     "|sha256=test_hash";

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

  auto ret = BasicString::Create(nullptr, false)->SerializeBundleHashingEvent(se);
  std::string got(ret.begin(), ret.end());

  std::string want = "action=BUNDLE|sha256=file_hash"
                     "|bundlehash=file_bundle_hash|bundlename=file_bundle_Name|bundleid="
                     "|bundlepath=file_bundle_path|path=file_path";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeDiskAppeared {
  NSDictionary *props = @{
    @"DADevicePath" : @"",
    @"DADeviceVendor" : @"vendor",
    @"DADeviceModel" : @"model",
    @"DAAppearanceTime" : @(1252487349),  // 2009-09-09 09:09:09
    @"DAVolumePath" : [NSURL URLWithString:@"path"],
    @"DAMediaBSDName" : @"bsd",
    @"DAVolumeKind" : @"apfs",
    @"DADeviceProtocol" : @"usb",
  };

  auto ret = BasicString::Create(nullptr, false)->SerializeDiskAppeared(props);
  std::string got(ret.begin(), ret.end());

  std::string want = "action=DISKAPPEAR|mount=path|volume=|bsdname=bsd|fs=apfs"
                     "|model=vendor model|serial=|bus=usb|dmgpath="
                     "|appearance=2040-09-09T09:09:09.000Z";

  XCTAssertCppStringEqual(got, want);
}

- (void)testSerializeDiskDisappeared {
  NSDictionary *props = @{
    @"DAVolumePath" : [NSURL URLWithString:@"path"],
    @"DAMediaBSDName" : @"bsd",
  };

  auto ret = BasicString::Create(nullptr, false)->SerializeDiskDisappeared(props);
  std::string got(ret.begin(), ret.end());

  std::string want = "action=DISKDISAPPEAR|mount=path|volume=|bsdname=bsd";

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
    {SNTEventStateBlockLongPath, "LONG_PATH"},
    {SNTEventStateAllowUnknown, "UNKNOWN"},
    {SNTEventStateAllowBinary, "BINARY"},
    {SNTEventStateAllowCertificate, "CERT"},
    {SNTEventStateAllowScope, "SCOPE"},
    {SNTEventStateAllowCompiler, "COMPILER"},
    {SNTEventStateAllowTransitive, "TRANSITIVE"},
    {SNTEventStateAllowPendingTransitive, "PENDING_TRANSITIVE"},
    {SNTEventStateAllowTeamID, "TEAMID"},
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
