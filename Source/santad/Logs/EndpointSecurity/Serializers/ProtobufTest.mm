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
#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/proc_info.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <time.h>
#include <uuid/uuid.h>
#include <cstring>

#include <google/protobuf/util/json_util.h>

#import "Source/common/SNTCachedDecision.h"
#include "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredEvent.h"
#include "Source/common/TestUtils.h"
#include "Source/common/santa_new.pb.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Protobuf.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#import "Source/santad/SNTDecisionCache.h"

using google::protobuf::Timestamp;
using google::protobuf::util::JsonPrintOptions;
using santa::santad::event_providers::endpoint_security::EnrichedClose;
using santa::santad::event_providers::endpoint_security::EnrichedEventType;
using santa::santad::event_providers::endpoint_security::EnrichedExchange;
using santa::santad::event_providers::endpoint_security::EnrichedExec;
using santa::santad::event_providers::endpoint_security::EnrichedExit;
using santa::santad::event_providers::endpoint_security::EnrichedFork;
using santa::santad::event_providers::endpoint_security::EnrichedLink;
using santa::santad::event_providers::endpoint_security::EnrichedMessage;
using santa::santad::event_providers::endpoint_security::EnrichedRename;
using santa::santad::event_providers::endpoint_security::EnrichedUnlink;
using santa::santad::event_providers::endpoint_security::Enricher;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::serializers::Protobuf;
using santa::santad::logs::endpoint_security::serializers::Serializer;

namespace pb = santa::pb;

namespace santa::santad::logs::endpoint_security::serializers {
extern void EncodeExitStatus(pb::Exit *pbExit, int exitStatus);
extern pb::Execution::Decision GetDecisionEnum(SNTEventState event_state);
extern pb::Execution::Reason GetReasonEnum(SNTEventState event_state);
extern pb::Execution::Mode GetModeEnum(SNTClientMode mode);
extern std::string_view GetFileDescriptorTypeName(uint32_t fdtype);
}  // namespace santa::santad::logs::endpoint_security::serializers

using santa::santad::logs::endpoint_security::serializers::EncodeExitStatus;
using santa::santad::logs::endpoint_security::serializers::GetDecisionEnum;
using santa::santad::logs::endpoint_security::serializers::GetFileDescriptorTypeName;
using santa::santad::logs::endpoint_security::serializers::GetModeEnum;
using santa::santad::logs::endpoint_security::serializers::GetReasonEnum;

JsonPrintOptions DefaultJsonPrintOptions() {
  JsonPrintOptions options;
  options.always_print_enums_as_ints = false;
  options.always_print_primitive_fields = false;
  options.preserve_proto_field_names = true;
  options.add_whitespace = true;
  return options;
}

NSString *TestJsonPath(NSString *jsonFileName, uint32_t version) {
  static dispatch_once_t onceToken;
  static NSString *testPath;
  static NSString *testDataRepoPath = @"santa/Source/santad/testdata/protobuf";
  NSString *testDataRepoVersionPath = [NSString stringWithFormat:@"v%u", version];

  dispatch_once(&onceToken, ^{
    testPath = [NSString pathWithComponents:@[
      [[[NSProcessInfo processInfo] environment] objectForKey:@"TEST_SRCDIR"], testDataRepoPath
    ]];
  });

  return [NSString pathWithComponents:@[ testPath, testDataRepoVersionPath, jsonFileName ]];
}

NSString *EventTypeToFilename(es_event_type_t eventType) {
  switch (eventType) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE: return @"close.json";
    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA: return @"exchangedata.json";
    case ES_EVENT_TYPE_NOTIFY_EXEC: return @"exec.json";
    case ES_EVENT_TYPE_NOTIFY_EXIT: return @"exit.json";
    case ES_EVENT_TYPE_NOTIFY_FORK: return @"fork.json";
    case ES_EVENT_TYPE_NOTIFY_LINK: return @"link.json";
    case ES_EVENT_TYPE_NOTIFY_RENAME: return @"rename.json";
    case ES_EVENT_TYPE_NOTIFY_UNLINK: return @"unlink.json";
    default: XCTFail(@"Unhandled event type: %d", eventType); return nil;
  }
}

NSString *LoadTestJson(NSString *jsonFileName, uint32_t version) {
  NSError *err = nil;
  NSString *jsonData = [NSString stringWithContentsOfFile:TestJsonPath(jsonFileName, version)
                                                 encoding:NSUTF8StringEncoding
                                                    error:&err];

  if (err) {
    XCTFail(@"Failed to load test data \"%@\": %@", jsonFileName, err);
  }

  return jsonData;
}

bool CompareTime(const Timestamp &timestamp, struct timespec ts) {
  return timestamp.seconds() == ts.tv_sec && timestamp.nanos() == ts.tv_nsec;
}

void CheckSantaMessage(const pb::SantaMessage &santaMsg, const es_message_t &esMsg,
                       const uuid_t &uuid, struct timespec enrichmentTime) {
  uuid_string_t uuidStr;
  uuid_unparse_lower(uuid, uuidStr);

  XCTAssertEqual(strcmp(santaMsg.uuid().c_str(), uuidStr), 0);
  XCTAssertTrue(CompareTime(santaMsg.processed_time(), enrichmentTime));
  XCTAssertTrue(CompareTime(santaMsg.event_time(), esMsg.time));
}

const google::protobuf::Message &SantaMessageEvent(const pb::SantaMessage &santaMsg) {
  switch (santaMsg.event_case()) {
    case santa::pb::SantaMessage::kExecution: return santaMsg.execution();
    case santa::pb::SantaMessage::kFork: return santaMsg.fork();
    case santa::pb::SantaMessage::kExit: return santaMsg.exit();
    case santa::pb::SantaMessage::kClose: return santaMsg.close();
    case santa::pb::SantaMessage::kRename: return santaMsg.rename();
    case santa::pb::SantaMessage::kUnlink: return santaMsg.unlink();
    case santa::pb::SantaMessage::kLink: return santaMsg.link();
    case santa::pb::SantaMessage::kExchangedata: return santaMsg.exchangedata();
    case santa::pb::SantaMessage::kDisk: return santaMsg.disk();
    case santa::pb::SantaMessage::kBundle: return santaMsg.bundle();
    case santa::pb::SantaMessage::kAllowlist: return santaMsg.allowlist();
    case santa::pb::SantaMessage::EVENT_NOT_SET:
      XCTFail(@"Protobuf message SantaMessage did not set an 'event' field");
      OS_FALLTHROUGH;
    default:
      [NSException raise:@"Required protobuf field not set"
                  format:@"SantaMessage missing required field 'event'"];
      abort();
  }
}

std::string ConvertMessageToJsonString(const pb::SantaMessage &santaMsg) {
  JsonPrintOptions options = DefaultJsonPrintOptions();
  const google::protobuf::Message &message = SantaMessageEvent(santaMsg);

  std::string json;
  google::protobuf::util::MessageToJsonString(message, &json, options);
  return json;
}

void CheckProto(const pb::SantaMessage &santaMsg, std::shared_ptr<EnrichedMessage> enrichedMsg) {
  return std::visit(
    [santaMsg](const EnrichedEventType &enrichedEvent) {
      CheckSantaMessage(santaMsg, enrichedEvent.es_msg(), enrichedEvent.uuid(),
                        enrichedEvent.enrichment_time());
      NSString *wantData = LoadTestJson(EventTypeToFilename(enrichedEvent.es_msg().event_type),
                                        enrichedEvent.es_msg().version);
      std::string got = ConvertMessageToJsonString(santaMsg);

      XCTAssertEqualObjects([NSString stringWithUTF8String:got.c_str()], wantData);
    },
    enrichedMsg->GetEnrichedMessage());
}

void SerializeAndCheck(es_event_type_t eventType,
                       void (^messageSetup)(std::shared_ptr<MockEndpointSecurityAPI>,
                                            es_message_t *)) {
  std::shared_ptr<MockEndpointSecurityAPI> mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  for (uint32_t cur_version = 1; cur_version <= MaxSupportedESMessageVersionForCurrentOS();
       cur_version++) {
    if (cur_version == 3) {
      // Note: Version 3 was only in a macOS beta.
      continue;
    }

    es_file_t procFile = MakeESFile("foo", MakeStat(100));
    es_file_t ttyFile = MakeESFile("footty", MakeStat(200));
    es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
    es_message_t esMsg = MakeESMessage(eventType, &proc);
    esMsg.process->tty = &ttyFile;
    esMsg.version = cur_version;

    mockESApi->SetExpectationsRetainReleaseMessage(&esMsg);

    messageSetup(mockESApi, &esMsg);

    std::shared_ptr<Serializer> bs = Protobuf::Create(mockESApi);
    std::shared_ptr<EnrichedMessage> enrichedMsg = Enricher().Enrich(Message(mockESApi, &esMsg));

    std::vector<uint8_t> vec = bs->SerializeMessage(enrichedMsg);
    std::string protoStr(vec.begin(), vec.end());

    pb::SantaMessage santaMsg;
    XCTAssertTrue(santaMsg.ParseFromString(protoStr));

    CheckProto(santaMsg, enrichedMsg);
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

@interface ProtobufTest : XCTestCase
@property id mockConfigurator;
@property id mockDecisionCache;
@property SNTCachedDecision *testCachedDecision;
@end

@implementation ProtobufTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator enableMachineIDDecoration]).andReturn(YES);
  OCMStub([self.mockConfigurator machineID]).andReturn(@"my_machine_id");

  self.testCachedDecision = [[SNTCachedDecision alloc] init];
  self.testCachedDecision.decision = SNTEventStateAllowBinary;
  self.testCachedDecision.decisionExtra = @"extra!";
  self.testCachedDecision.sha256 = @"1234_file_hash";
  self.testCachedDecision.quarantineURL = @"google.com";
  self.testCachedDecision.certSHA256 = @"5678_cert_hash";

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
  __block es_file_t file = MakeESFile("close_file", MakeStat(300));

  SerializeAndCheck(ES_EVENT_TYPE_NOTIFY_CLOSE,
                    ^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi, es_message_t *esMsg) {
                      esMsg->event.close.modified = true;
                      esMsg->event.close.target = &file;
                    });
}

- (void)testSerializeMessageExchange {
  __block es_file_t file1 = MakeESFile("exchange_file_1", MakeStat(300));
  __block es_file_t file2 = MakeESFile("exchange_file_1", MakeStat(400));

  SerializeAndCheck(ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
                    ^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi, es_message_t *esMsg) {
                      esMsg->event.exchangedata.file1 = &file1;
                      esMsg->event.exchangedata.file2 = &file2;
                    });
}

- (void)testGetDecisionEnum {
  std::map<SNTEventState, pb::Execution::Decision> stateToDecision = {
    {SNTEventStateUnknown, pb::Execution::DECISION_UNKNOWN},
    {SNTEventStateBundleBinary, pb::Execution::DECISION_UNKNOWN},
    {SNTEventStateBlockUnknown, pb::Execution::DECISION_DENY},
    {SNTEventStateBlockBinary, pb::Execution::DECISION_DENY},
    {SNTEventStateBlockCertificate, pb::Execution::DECISION_DENY},
    {SNTEventStateBlockScope, pb::Execution::DECISION_DENY},
    {SNTEventStateBlockTeamID, pb::Execution::DECISION_DENY},
    {SNTEventStateBlockLongPath, pb::Execution::DECISION_DENY},
    {SNTEventStateAllowUnknown, pb::Execution::DECISION_ALLOW},
    {SNTEventStateAllowBinary, pb::Execution::DECISION_ALLOW},
    {SNTEventStateAllowCertificate, pb::Execution::DECISION_ALLOW},
    {SNTEventStateAllowScope, pb::Execution::DECISION_ALLOW},
    {SNTEventStateAllowCompiler, pb::Execution::DECISION_ALLOW},
    {SNTEventStateAllowTransitive, pb::Execution::DECISION_ALLOW},
    {SNTEventStateAllowPendingTransitive, pb::Execution::DECISION_ALLOW},
    {SNTEventStateAllowTeamID, pb::Execution::DECISION_ALLOW},
  };

  for (const auto &kv : stateToDecision) {
    XCTAssertEqual(GetDecisionEnum(kv.first), kv.second, @"Bad decision for state: %ld", kv.first);
  }
}

- (void)testGetReasonEnum {
  std::map<SNTEventState, pb::Execution::Reason> stateToReason = {
    {SNTEventStateUnknown, pb::Execution::REASON_NOT_RUNNING},
    {SNTEventStateBundleBinary, pb::Execution::REASON_NOT_RUNNING},
    {SNTEventStateBlockUnknown, pb::Execution::REASON_UNKNOWN},
    {SNTEventStateBlockBinary, pb::Execution::REASON_BINARY},
    {SNTEventStateBlockCertificate, pb::Execution::REASON_CERT},
    {SNTEventStateBlockScope, pb::Execution::REASON_SCOPE},
    {SNTEventStateBlockTeamID, pb::Execution::REASON_TEAM_ID},
    {SNTEventStateBlockLongPath, pb::Execution::REASON_LONG_PATH},
    {SNTEventStateAllowUnknown, pb::Execution::REASON_UNKNOWN},
    {SNTEventStateAllowBinary, pb::Execution::REASON_BINARY},
    {SNTEventStateAllowCertificate, pb::Execution::REASON_CERT},
    {SNTEventStateAllowScope, pb::Execution::REASON_SCOPE},
    {SNTEventStateAllowCompiler, pb::Execution::REASON_COMPILER},
    {SNTEventStateAllowTransitive, pb::Execution::REASON_TRANSITIVE},
    {SNTEventStateAllowPendingTransitive, pb::Execution::REASON_PENDING_TRANSITIVE},
    {SNTEventStateAllowTeamID, pb::Execution::REASON_TEAM_ID},
  };

  for (const auto &kv : stateToReason) {
    XCTAssertEqual(GetReasonEnum(kv.first), kv.second, @"Bad reason for state: %ld", kv.first);
  }
}

- (void)testGetModeEnum {
  std::map<SNTClientMode, pb::Execution::Mode> clientModeToExecMode = {
    {SNTClientModeUnknown, pb::Execution::MODE_UNKNOWN},
    {SNTClientModeMonitor, pb::Execution::MODE_MONITOR},
    {SNTClientModeLockdown, pb::Execution::MODE_LOCKDOWN},
    {(SNTClientMode)123, pb::Execution::MODE_UNKNOWN},
  };

  for (const auto &kv : clientModeToExecMode) {
    XCTAssertEqual(GetModeEnum(kv.first), kv.second, @"Bad mode for state: %ld", kv.first);
  }
}

- (void)testGetFileDescriptorTypeName {
  std::map<uint32_t, std::string_view> fdtypeToName = {
    {PROX_FDTYPE_ATALK, "ATALK"},
    {PROX_FDTYPE_VNODE, "VNODE"},
    {PROX_FDTYPE_SOCKET, "SOCKET"},
    {PROX_FDTYPE_PSHM, "PSHM"},
    {PROX_FDTYPE_PSEM, "PSEM"},
    {PROX_FDTYPE_KQUEUE, "KQUEUE"},
    {PROX_FDTYPE_PIPE, "PIPE"},
    {PROX_FDTYPE_FSEVENTS, "FSEVENTS"},
    {PROX_FDTYPE_NETPOLICY, "NETPOLICY"},
    {10 /* PROX_FDTYPE_CHANNEL */, "CHANNEL"},
    {11 /* PROX_FDTYPE_NEXUS */, "NEXUS"},
  };

  for (const auto &kv : fdtypeToName) {
    XCTAssertEqual(GetFileDescriptorTypeName(kv.first), kv.second,
                   @"Bad fd type name for fdtype: %u", kv.first);
  }
}

- (void)testSerializeMessageExec {
  es_file_t procFileTarget = MakeESFile("fooexec", MakeStat(300));
  __block es_process_t procTarget =
    MakeESProcess(&procFileTarget, MakeAuditToken(23, 45), MakeAuditToken(67, 89));
  __block es_file_t fileCwd = MakeESFile("cwd", MakeStat(400));
  __block es_file_t fileScript = MakeESFile("script.sh", MakeStat(500));
  __block es_fd_t fd1 = {.fd = 1, .fdtype = PROX_FDTYPE_VNODE};
  __block es_fd_t fd2 = {.fd = 2, .fdtype = PROX_FDTYPE_SOCKET};
  __block es_fd_t fd3 = {.fd = 3, .fdtype = PROX_FDTYPE_PIPE, .pipe = {.pipe_id = 123}};

  procTarget.codesigning_flags = CS_SIGNED | CS_HARD | CS_KILL;
  memset(procTarget.cdhash, 'A', sizeof(procTarget.cdhash));
  procTarget.signing_id = MakeESStringToken("my_signing_id");
  procTarget.team_id = MakeESStringToken("my_team_id");

  SerializeAndCheck(ES_EVENT_TYPE_NOTIFY_EXEC, ^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                                 es_message_t *esMsg) {
    esMsg->event.exec.target = &procTarget;
    esMsg->event.exec.cwd = &fileCwd;
    esMsg->event.exec.script = &fileScript;

    EXPECT_CALL(*mockESApi, ExecArgCount).WillOnce(testing::Return(3));
    EXPECT_CALL(*mockESApi, ExecArg)
      .WillOnce(testing::Return(MakeESStringToken("exec_path")))
      .WillOnce(testing::Return(MakeESStringToken("-l")))
      .WillOnce(testing::Return(MakeESStringToken("--foo")));

    EXPECT_CALL(*mockESApi, ExecEnvCount).WillOnce(testing::Return(2));
    EXPECT_CALL(*mockESApi, ExecEnv)
      .WillOnce(testing::Return(MakeESStringToken("ENV_PATH=/path/to/bin:/and/another")))
      .WillOnce(testing::Return(MakeESStringToken("DEBUG=1")));

    EXPECT_CALL(*mockESApi, ExecFDCount).WillOnce(testing::Return(3));
    EXPECT_CALL(*mockESApi, ExecFD)
      .WillOnce(testing::Return(&fd1))
      .WillOnce(testing::Return(&fd2))
      .WillOnce(testing::Return(&fd3));
  });
}

- (void)testSerializeMessageExit {
  SerializeAndCheck(ES_EVENT_TYPE_NOTIFY_EXIT,
                    ^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi, es_message_t *esMsg) {
                      esMsg->event.exit.stat = W_EXITCODE(1, 0);
                    });
}

- (void)testEncodeExitStatus {
  {
    pb::Exit pbExit;
    EncodeExitStatus(&pbExit, W_EXITCODE(1, 0));
    XCTAssertTrue(pbExit.has_exited());
    XCTAssertEqual(1, pbExit.exited().exit_status());
  }

  {
    pb::Exit pbExit;
    EncodeExitStatus(&pbExit, W_EXITCODE(2, SIGUSR1));
    XCTAssertTrue(pbExit.has_signaled());
    XCTAssertEqual(SIGUSR1, pbExit.signaled().signal());
  }

  {
    pb::Exit pbExit;
    EncodeExitStatus(&pbExit, W_STOPCODE(SIGSTOP));
    XCTAssertTrue(pbExit.has_stopped());
    XCTAssertEqual(SIGSTOP, pbExit.stopped().signal());
  }
}

- (void)testSerializeMessageFork {
  __block es_file_t procFileChild = MakeESFile("foo_child", MakeStat(300));
  __block es_file_t ttyFileChild = MakeESFile("footty", MakeStat(400));
  __block es_process_t procChild =
    MakeESProcess(&procFileChild, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  procChild.tty = &ttyFileChild;

  SerializeAndCheck(ES_EVENT_TYPE_NOTIFY_FORK,
                    ^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi, es_message_t *esMsg) {
                      esMsg->event.fork.child = &procChild;
                    });
}

- (void)testSerializeMessageLink {
  __block es_file_t fileSource = MakeESFile("source", MakeStat(300));
  __block es_file_t fileTargetDir = MakeESFile("target_dir");
  es_string_token_t targetTok = MakeESStringToken("target_file");

  SerializeAndCheck(ES_EVENT_TYPE_NOTIFY_LINK,
                    ^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi, es_message_t *esMsg) {
                      esMsg->event.link.source = &fileSource;
                      esMsg->event.link.target_dir = &fileTargetDir;
                      esMsg->event.link.target_filename = targetTok;
                    });
}

- (void)testSerializeMessageRename {
  __block es_file_t fileSource = MakeESFile("source", MakeStat(300));
  __block es_file_t fileTargetDir = MakeESFile("target_dir");
  es_string_token_t targetTok = MakeESStringToken("target_file");

  SerializeAndCheck(ES_EVENT_TYPE_NOTIFY_RENAME,
                    ^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi, es_message_t *esMsg) {
                      esMsg->event.rename.source = &fileSource;
                      // Test new and existing destination types
                      if (esMsg->version == 4) {
                        esMsg->event.rename.destination.existing_file = &fileTargetDir;
                        esMsg->event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
                      } else {
                        esMsg->event.rename.destination.new_path.dir = &fileTargetDir;
                        esMsg->event.rename.destination.new_path.filename = targetTok;
                        esMsg->event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
                      }
                    });
}

- (void)testSerializeMessageUnlink {
  __block es_file_t fileTarget = MakeESFile("unlink_file", MakeStat(300));
  __block es_file_t fileTargetParent = MakeESFile("unlink_file_parent", MakeStat(400));

  SerializeAndCheck(ES_EVENT_TYPE_NOTIFY_UNLINK,
                    ^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi, es_message_t *esMsg) {
                      esMsg->event.unlink.target = &fileTarget;
                      esMsg->event.unlink.parent_dir = &fileTargetParent;
                    });
}

- (void)testSerializeAllowlist {
  std::shared_ptr<MockEndpointSecurityAPI> mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  for (uint32_t cur_version = 1; cur_version <= MaxSupportedESMessageVersionForCurrentOS();
       cur_version++) {
    if (cur_version == 3) {
      // Note: Version 3 was only in a macOS beta.
      continue;
    }

    es_file_t procFile = MakeESFile("foo", MakeStat(100));
    es_file_t ttyFile = MakeESFile("footty", MakeStat(200));
    es_file_t closeFile = MakeESFile("close_file", MakeStat(300));
    es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
    es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &proc);
    esMsg.process->tty = &ttyFile;
    esMsg.version = cur_version;
    esMsg.event.close.modified = true;
    esMsg.event.close.target = &closeFile;

    mockESApi->SetExpectationsRetainReleaseMessage(&esMsg);

    std::shared_ptr<Serializer> bs = Protobuf::Create(mockESApi);

    std::vector<uint8_t> vec = bs->SerializeAllowlist(Message(mockESApi, &esMsg), "hash_value");
    std::string protoStr(vec.begin(), vec.end());

    pb::SantaMessage santaMsg;
    XCTAssertTrue(santaMsg.ParseFromString(protoStr));

    NSString *wantData = LoadTestJson(@"allowlist.json", esMsg.version);
    std::string got = ConvertMessageToJsonString(santaMsg);

    XCTAssertEqualObjects([NSString stringWithUTF8String:got.c_str()], wantData);
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testSerializeBundleHashingEvent {
  SNTStoredEvent *se = [[SNTStoredEvent alloc] init];

  se.fileSHA256 = @"file_hash";
  se.fileBundleHash = @"file_bundle_hash";
  se.fileBundleName = @"file_bundle_name";
  se.fileBundleID = nil;
  se.fileBundlePath = @"file_bundle_path";
  se.filePath = @"file_path";

  std::shared_ptr<MockEndpointSecurityAPI> mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<Serializer> bs = Protobuf::Create(mockESApi);

  std::vector<uint8_t> vec = bs->SerializeBundleHashingEvent(se);
  std::string protoStr(vec.begin(), vec.end());

  pb::SantaMessage santaMsg;
  XCTAssertTrue(santaMsg.ParseFromString(protoStr));

  XCTAssertTrue(santaMsg.has_bundle());

  const pb::Bundle &pbBundle = santaMsg.bundle();

  pb::Hash pbHash = pbBundle.file_hash();
  XCTAssertEqualObjects(@(pbHash.hash().c_str()), se.fileSHA256);
  XCTAssertEqual(pbHash.type(), pb::Hash::HASH_ALGO_SHA256);

  pbHash = pbBundle.bundle_hash();
  XCTAssertEqualObjects(@(pbHash.hash().c_str()), se.fileBundleHash);
  XCTAssertEqual(pbHash.type(), pb::Hash::HASH_ALGO_SHA256);

  XCTAssertEqualObjects(@(pbBundle.bundle_name().c_str()), se.fileBundleName);
  XCTAssertEqualObjects(@(pbBundle.bundle_id().c_str()), @"");
  XCTAssertEqualObjects(@(pbBundle.bundle_path().c_str()), se.fileBundlePath);
  XCTAssertEqualObjects(@(pbBundle.path().c_str()), se.filePath);

}

@end
