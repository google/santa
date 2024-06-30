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
#include <google/protobuf/json/json.h>
#include <gtest/gtest.h>
#include <sys/proc_info.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <time.h>
#include <uuid/uuid.h>
#include <cstring>

#include "Source/common/Platform.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredEvent.h"
#include "Source/common/TestUtils.h"
#include "Source/common/santa_proto_include_wrapper.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Protobuf.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#import "Source/santad/SNTDecisionCache.h"
#include "absl/status/status.h"
#include "google/protobuf/any.pb.h"
#include "google/protobuf/timestamp.pb.h"

using google::protobuf::Timestamp;
using JsonPrintOptions = google::protobuf::json::PrintOptions;
using JsonParseOptions = ::google::protobuf::json::ParseOptions;
using google::protobuf::json::JsonStringToMessage;
using google::protobuf::json::MessageToJsonString;
using santa::santad::event_providers::endpoint_security::EnrichedEventType;
using santa::santad::event_providers::endpoint_security::EnrichedMessage;
using santa::santad::event_providers::endpoint_security::Enricher;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::serializers::Protobuf;
using santa::santad::logs::endpoint_security::serializers::Serializer;

namespace pbv1 = ::santa::pb::v1;

namespace santa::santad::logs::endpoint_security::serializers {
extern void EncodeExitStatus(::pbv1::Exit *pbExit, int exitStatus);
extern void EncodeEntitlements(::pbv1::Execution *pb_exec, SNTCachedDecision *cd);
extern ::pbv1::Execution::Decision GetDecisionEnum(SNTEventState event_state);
extern ::pbv1::Execution::Reason GetReasonEnum(SNTEventState event_state);
extern ::pbv1::Execution::Mode GetModeEnum(SNTClientMode mode);
extern ::pbv1::FileDescriptor::FDType GetFileDescriptorType(uint32_t fdtype);
extern ::pbv1::FileAccess::AccessType GetAccessType(es_event_type_t event_type);
extern ::pbv1::FileAccess::PolicyDecision GetPolicyDecision(FileAccessPolicyDecision decision);
#if HAVE_MACOS_13
extern ::pbv1::SocketAddress::Type GetSocketAddressType(es_address_type_t type);
extern ::pbv1::OpenSSHLogin::Result GetOpenSSHLoginResultType(es_openssh_login_result_type_t type);
#endif
}  // namespace santa::santad::logs::endpoint_security::serializers

using santa::santad::logs::endpoint_security::serializers::EncodeEntitlements;
using santa::santad::logs::endpoint_security::serializers::EncodeExitStatus;
using santa::santad::logs::endpoint_security::serializers::GetAccessType;
using santa::santad::logs::endpoint_security::serializers::GetDecisionEnum;
using santa::santad::logs::endpoint_security::serializers::GetFileDescriptorType;
using santa::santad::logs::endpoint_security::serializers::GetModeEnum;
using santa::santad::logs::endpoint_security::serializers::GetPolicyDecision;
using santa::santad::logs::endpoint_security::serializers::GetReasonEnum;
#if HAVE_MACOS_13
using santa::santad::logs::endpoint_security::serializers::GetOpenSSHLoginResultType;
using santa::santad::logs::endpoint_security::serializers::GetSocketAddressType;
#endif

@interface ProtobufTest : XCTestCase
@property id mockConfigurator;
@property id mockDecisionCache;
@property SNTCachedDecision *testCachedDecision;
@end

JsonPrintOptions DefaultJsonPrintOptions() {
  JsonPrintOptions options;
  options.always_print_enums_as_ints = false;
  options.always_print_fields_with_no_presence = false;
  options.preserve_proto_field_names = true;
  options.add_whitespace = true;
  return options;
}

NSString *ConstructFilename(es_event_type_t eventType, NSString *variant = nil) {
  NSString *name;
  switch (eventType) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE: name = @"close"; break;
    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA: name = @"exchangedata"; break;
    case ES_EVENT_TYPE_NOTIFY_EXEC: name = @"exec"; break;
    case ES_EVENT_TYPE_NOTIFY_EXIT: name = @"exit"; break;
    case ES_EVENT_TYPE_NOTIFY_FORK: name = @"fork"; break;
    case ES_EVENT_TYPE_NOTIFY_LINK: name = @"link"; break;
    case ES_EVENT_TYPE_NOTIFY_RENAME: name = @"rename"; break;
    case ES_EVENT_TYPE_NOTIFY_UNLINK: name = @"unlink"; break;
    case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED: name = @"cs_invalidated"; break;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN: name = @"lw_session_login"; break;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT: name = @"lw_session_logout"; break;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK: name = @"lw_session_lock"; break;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK: name = @"lw_session_unlock"; break;
    case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH: name = @"screensharing_attach"; break;
    case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH: name = @"screensharing_detach"; break;
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN: name = @"openssh_login"; break;
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT: name = @"openssh_logout"; break;
    default: XCTFail(@"Unhandled event type: %d", eventType); return nil;
  }

  if (variant) {
    return [NSString stringWithFormat:@"%@_%@.json", name, variant];
  } else {
    return [NSString stringWithFormat:@"%@.json", name];
  }
}

NSString *LoadTestJson(NSString *jsonFileName, uint32_t version) {
  if (!jsonFileName) {
    return nil;
  }

  NSString *path = [NSString pathWithComponents:@[
    [[NSBundle bundleForClass:[ProtobufTest class]] resourcePath],
    @"protobuf",
    [NSString stringWithFormat:@"v%u", version],
    jsonFileName,
  ]];

  NSError *err = nil;
  NSString *jsonData = [NSString stringWithContentsOfFile:path
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

const google::protobuf::Message &SantaMessageEvent(const ::pbv1::SantaMessage &santaMsg) {
  switch (santaMsg.event_case()) {
    case ::pbv1::SantaMessage::kExecution: return santaMsg.execution();
    case ::pbv1::SantaMessage::kFork: return santaMsg.fork();
    case ::pbv1::SantaMessage::kExit: return santaMsg.exit();
    case ::pbv1::SantaMessage::kClose: return santaMsg.close();
    case ::pbv1::SantaMessage::kRename: return santaMsg.rename();
    case ::pbv1::SantaMessage::kUnlink: return santaMsg.unlink();
    case ::pbv1::SantaMessage::kLink: return santaMsg.link();
    case ::pbv1::SantaMessage::kExchangedata: return santaMsg.exchangedata();
    case ::pbv1::SantaMessage::kDisk: return santaMsg.disk();
    case ::pbv1::SantaMessage::kBundle: return santaMsg.bundle();
    case ::pbv1::SantaMessage::kAllowlist: return santaMsg.allowlist();
    case ::pbv1::SantaMessage::kFileAccess: return santaMsg.file_access();
    case ::pbv1::SantaMessage::kCodesigningInvalidated: return santaMsg.codesigning_invalidated();
    case ::pbv1::SantaMessage::kLoginWindowSession: return santaMsg.login_window_session();
    case ::pbv1::SantaMessage::kScreenSharing: return santaMsg.screen_sharing();
    case ::pbv1::SantaMessage::kOpenSsh: return santaMsg.open_ssh();
    case ::pbv1::SantaMessage::EVENT_NOT_SET:
      XCTFail(@"Protobuf message SantaMessage did not set an 'event' field");
      OS_FALLTHROUGH;
    default:
      [NSException raise:@"Required protobuf field not set"
                  format:@"SantaMessage missing required field 'event'"];
      abort();
  }
}

std::string ConvertMessageToJsonString(const ::pbv1::SantaMessage &santaMsg) {
  JsonPrintOptions options = DefaultJsonPrintOptions();
  const google::protobuf::Message &message = SantaMessageEvent(santaMsg);

  std::string json;
  XCTAssertTrue(MessageToJsonString(message, &json, options).ok());
  return json;
}

NSDictionary *FindDelta(NSDictionary *want, NSDictionary *got) {
  NSMutableDictionary *delta = [NSMutableDictionary dictionary];
  delta[@"want"] = [NSMutableDictionary dictionary];
  delta[@"got"] = [NSMutableDictionary dictionary];

  // Find objects in `want` that don't exist or are different in `got`.
  [want enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
    id otherObj = got[key];

    if (!otherObj) {
      delta[@"want"][key] = obj;
      delta[@"got"][key] = @"Key missing";
    } else if (![obj isEqual:otherObj]) {
      delta[@"want"][key] = obj;
      delta[@"got"][key] = otherObj;
    }
  }];

  // Find objects in `got` that don't exist in `want`
  [got enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
    id aObj = want[key];

    if (!aObj) {
      delta[@"want"][key] = @"Key missing";
      delta[@"got"][key] = obj;
    }
  }];

  return [delta[@"want"] count] > 0 ? delta : nil;
}

void SerializeAndCheck(es_event_type_t eventType,
                       void (^messageSetup)(std::shared_ptr<MockEndpointSecurityAPI>,
                                            es_message_t *),
                       SNTDecisionCache *decisionCache, bool json, NSString *variant) {
  std::shared_ptr<MockEndpointSecurityAPI> mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  for (uint32_t cur_version = MinSupportedESMessageVersion(eventType);
       cur_version <= MaxSupportedESMessageVersionForCurrentOS(); cur_version++) {
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

    mockESApi->SetExpectationsRetainReleaseMessage();

    messageSetup(mockESApi, &esMsg);

    std::shared_ptr<Serializer> bs = Protobuf::Create(mockESApi, decisionCache, json);
    std::unique_ptr<EnrichedMessage> enrichedMsg = Enricher().Enrich(Message(mockESApi, &esMsg));

    // Copy some values we need to check later before the object is moved out of this funciton
    struct timespec enrichmentTime;
    struct timespec msgTime;
    NSString *wantData = std::visit(
      [&msgTime, &enrichmentTime, variant](const EnrichedEventType &enrichedEvent) {
        msgTime = enrichedEvent->time;
        enrichmentTime = enrichedEvent.enrichment_time();

        return LoadTestJson(ConstructFilename(enrichedEvent->event_type, variant),
                            enrichedEvent->version);
      },
      enrichedMsg->GetEnrichedMessage());

    std::vector<uint8_t> vec = bs->SerializeMessage(std::move(enrichedMsg));
    std::string protoStr(vec.begin(), vec.end());

    ::pbv1::SantaMessage santaMsg;
    std::string gotData;

    if (json) {
      // Parse the jsonified string into the protobuf
      JsonParseOptions options;
      options.ignore_unknown_fields = true;
      absl::Status status = JsonStringToMessage(protoStr, &santaMsg, options);
      XCTAssertTrue(status.ok());
      gotData = ConvertMessageToJsonString(santaMsg);
    } else {
      XCTAssertTrue(santaMsg.ParseFromString(protoStr));
      gotData = ConvertMessageToJsonString(santaMsg);
    }

    XCTAssertTrue(CompareTime(santaMsg.processed_time(), enrichmentTime));
    XCTAssertTrue(CompareTime(santaMsg.event_time(), msgTime));

    // Convert JSON strings to objects and compare each key-value set.
    NSError *jsonError;
    NSData *objectData = [wantData dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *wantJSONDict =
      [NSJSONSerialization JSONObjectWithData:objectData
                                      options:NSJSONReadingMutableContainers
                                        error:&jsonError];
    XCTAssertNil(jsonError, @"failed to parse want data as JSON");
    NSDictionary *gotJSONDict = [NSJSONSerialization
      JSONObjectWithData:[NSData dataWithBytes:gotData.data() length:gotData.length()]
                 options:NSJSONReadingMutableContainers
                   error:&jsonError];
    XCTAssertNil(jsonError, @"failed to parse got data as JSON");

    XCTAssertNil(FindDelta(wantJSONDict, gotJSONDict));
    // Note: Uncomment this line to help create testfile JSON when the assert above fails
    // XCTAssertEqualObjects([NSString stringWithUTF8String:gotData.c_str()], wantData);
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

void SerializeAndCheckNonESEvents(
  uint32_t minAssociatedESVersion, es_event_type_t eventType, NSString *filename,
  void (^messageSetup)(std::shared_ptr<MockEndpointSecurityAPI>, es_message_t *),
  std::vector<uint8_t> (^RunSerializer)(std::shared_ptr<Serializer> serializer,
                                        const Message &msg)) {
  std::shared_ptr<MockEndpointSecurityAPI> mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();
  std::shared_ptr<Serializer> bs = Protobuf::Create(mockESApi, nil);

  for (uint32_t cur_version = minAssociatedESVersion;
       cur_version <= MaxSupportedESMessageVersionForCurrentOS(); cur_version++) {
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

    messageSetup(mockESApi, &esMsg);

    std::vector<uint8_t> vec = RunSerializer(bs, Message(mockESApi, &esMsg));

    std::string protoStr(vec.begin(), vec.end());

    ::pbv1::SantaMessage santaMsg;
    XCTAssertTrue(santaMsg.ParseFromString(protoStr));
    std::string got = ConvertMessageToJsonString(santaMsg);
    NSString *wantData = LoadTestJson(filename, esMsg.version);

    XCTAssertEqualObjects([NSString stringWithUTF8String:got.c_str()], wantData);
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

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
  self.testCachedDecision.decisionClientMode = SNTClientModeLockdown;
  self.testCachedDecision.entitlements = @{
    @"key_with_str_val" : @"bar",
    @"key_with_num_val" : @(1234),
    @"key_with_date_val" : [NSDate dateWithTimeIntervalSince1970:1699376402],
    @"key_with_data_val" : [@"Hello World" dataUsingEncoding:NSUTF8StringEncoding],
    @"key_with_arr_val" : @[ @"v1", @"v2", @"v3" ],
    @"key_with_arr_val_nested" : @[ @"v1", @"v2", @"v3", @[ @"nv1", @"nv2" ] ],
    @"key_with_arr_val_multitype" :
      @[ @"v1", @"v2", @"v3", @(123), [NSDate dateWithTimeIntervalSince1970:1699376402] ],
    @"key_with_dict_val" : @{@"k1" : @"v1", @"k2" : @"v2"},
    @"key_with_dict_val_nested" : @{
      @"k1" : @"v1",
      @"k2" : @"v2",
      @"k3" : @{@"nk1" : @"nv1", @"nk2" : [NSDate dateWithTimeIntervalSince1970:1699376402]}
    },
  };

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

- (void)serializeAndCheckEvent:(es_event_type_t)eventType
                  messageSetup:(void (^)(std::shared_ptr<MockEndpointSecurityAPI>,
                                         es_message_t *))messageSetup
                          json:(BOOL)json {
  SerializeAndCheck(eventType, messageSetup, self.mockDecisionCache, (bool)json, nil);
}

- (void)serializeAndCheckEvent:(es_event_type_t)eventType
                  messageSetup:(void (^)(std::shared_ptr<MockEndpointSecurityAPI>,
                                         es_message_t *))messageSetup {
  SerializeAndCheck(eventType, messageSetup, self.mockDecisionCache, false, nil);
}

- (void)serializeAndCheckEvent:(es_event_type_t)eventType
                  messageSetup:(void (^)(std::shared_ptr<MockEndpointSecurityAPI>,
                                         es_message_t *))messageSetup
                       variant:(NSString *)variant {
  SerializeAndCheck(eventType, messageSetup, self.mockDecisionCache, false, variant);
}

- (void)testSerializeMessageClose {
  __block es_file_t file = MakeESFile("close_file", MakeStat(300));

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_CLOSE
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.close.modified = true;
                    esMsg->event.close.target = &file;
                  }
                          json:NO];
}

- (void)testSerializeMessageExchange {
  __block es_file_t file1 = MakeESFile("exchange_file_1", MakeStat(300));
  __block es_file_t file2 = MakeESFile("exchange_file_1", MakeStat(400));

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.exchangedata.file1 = &file1;
                    esMsg->event.exchangedata.file2 = &file2;
                  }
                          json:NO];
}

- (void)testGetDecisionEnum {
  std::map<SNTEventState, ::pbv1::Execution::Decision> stateToDecision = {
    {SNTEventStateUnknown, ::pbv1::Execution::DECISION_UNKNOWN},
    {SNTEventStateBundleBinary, ::pbv1::Execution::DECISION_UNKNOWN},
    {SNTEventStateBlockUnknown, ::pbv1::Execution::DECISION_DENY},
    {SNTEventStateBlockBinary, ::pbv1::Execution::DECISION_DENY},
    {SNTEventStateBlockCertificate, ::pbv1::Execution::DECISION_DENY},
    {SNTEventStateBlockScope, ::pbv1::Execution::DECISION_DENY},
    {SNTEventStateBlockTeamID, ::pbv1::Execution::DECISION_DENY},
    {SNTEventStateBlockLongPath, ::pbv1::Execution::DECISION_DENY},
    {SNTEventStateAllowUnknown, ::pbv1::Execution::DECISION_ALLOW},
    {SNTEventStateAllowBinary, ::pbv1::Execution::DECISION_ALLOW},
    {SNTEventStateAllowCertificate, ::pbv1::Execution::DECISION_ALLOW},
    {SNTEventStateAllowScope, ::pbv1::Execution::DECISION_ALLOW},
    {SNTEventStateAllowCompiler, ::pbv1::Execution::DECISION_ALLOW},
    {SNTEventStateAllowTransitive, ::pbv1::Execution::DECISION_ALLOW},
    {SNTEventStateAllowPendingTransitive, ::pbv1::Execution::DECISION_ALLOW},
    {SNTEventStateAllowTeamID, ::pbv1::Execution::DECISION_ALLOW},
  };

  for (const auto &kv : stateToDecision) {
    XCTAssertEqual(GetDecisionEnum(kv.first), kv.second, @"Bad decision for state: %llu", kv.first);
  }
}

- (void)testGetReasonEnum {
  std::map<SNTEventState, ::pbv1::Execution::Reason> stateToReason = {
    {SNTEventStateUnknown, ::pbv1::Execution::REASON_NOT_RUNNING},
    {SNTEventStateBundleBinary, ::pbv1::Execution::REASON_NOT_RUNNING},
    {SNTEventStateBlockUnknown, ::pbv1::Execution::REASON_UNKNOWN},
    {SNTEventStateBlockBinary, ::pbv1::Execution::REASON_BINARY},
    {SNTEventStateBlockCertificate, ::pbv1::Execution::REASON_CERT},
    {SNTEventStateBlockScope, ::pbv1::Execution::REASON_SCOPE},
    {SNTEventStateBlockTeamID, ::pbv1::Execution::REASON_TEAM_ID},
    {SNTEventStateBlockSigningID, ::pbv1::Execution::REASON_SIGNING_ID},
    {SNTEventStateBlockCDHash, ::pbv1::Execution::REASON_CDHASH},
    {SNTEventStateBlockLongPath, ::pbv1::Execution::REASON_LONG_PATH},
    {SNTEventStateAllowUnknown, ::pbv1::Execution::REASON_UNKNOWN},
    {SNTEventStateAllowBinary, ::pbv1::Execution::REASON_BINARY},
    {SNTEventStateAllowCertificate, ::pbv1::Execution::REASON_CERT},
    {SNTEventStateAllowScope, ::pbv1::Execution::REASON_SCOPE},
    {SNTEventStateAllowCompiler, ::pbv1::Execution::REASON_COMPILER},
    {SNTEventStateAllowTransitive, ::pbv1::Execution::REASON_TRANSITIVE},
    {SNTEventStateAllowPendingTransitive, ::pbv1::Execution::REASON_PENDING_TRANSITIVE},
    {SNTEventStateAllowTeamID, ::pbv1::Execution::REASON_TEAM_ID},
    {SNTEventStateAllowSigningID, ::pbv1::Execution::REASON_SIGNING_ID},
    {SNTEventStateAllowCDHash, ::pbv1::Execution::REASON_CDHASH},
  };

  for (const auto &kv : stateToReason) {
    XCTAssertEqual(GetReasonEnum(kv.first), kv.second, @"Bad reason for state: %llu", kv.first);
  }
}

- (void)testGetModeEnum {
  std::map<SNTClientMode, ::pbv1::Execution::Mode> clientModeToExecMode = {
    {SNTClientModeUnknown, ::pbv1::Execution::MODE_UNKNOWN},
    {SNTClientModeMonitor, ::pbv1::Execution::MODE_MONITOR},
    {SNTClientModeLockdown, ::pbv1::Execution::MODE_LOCKDOWN},
    {(SNTClientMode)123, ::pbv1::Execution::MODE_UNKNOWN},
  };

  for (const auto &kv : clientModeToExecMode) {
    XCTAssertEqual(GetModeEnum(kv.first), kv.second, @"Bad mode for client mode: %ld", kv.first);
  }
}

- (void)testGetFileDescriptorType {
  std::map<uint32_t, ::pbv1::FileDescriptor::FDType> fdtypeToEnumType = {
    {PROX_FDTYPE_ATALK, ::pbv1::FileDescriptor::FD_TYPE_ATALK},
    {PROX_FDTYPE_VNODE, ::pbv1::FileDescriptor::FD_TYPE_VNODE},
    {PROX_FDTYPE_SOCKET, ::pbv1::FileDescriptor::FD_TYPE_SOCKET},
    {PROX_FDTYPE_PSHM, ::pbv1::FileDescriptor::FD_TYPE_PSHM},
    {PROX_FDTYPE_PSEM, ::pbv1::FileDescriptor::FD_TYPE_PSEM},
    {PROX_FDTYPE_KQUEUE, ::pbv1::FileDescriptor::FD_TYPE_KQUEUE},
    {PROX_FDTYPE_PIPE, ::pbv1::FileDescriptor::FD_TYPE_PIPE},
    {PROX_FDTYPE_FSEVENTS, ::pbv1::FileDescriptor::FD_TYPE_FSEVENTS},
    {PROX_FDTYPE_NETPOLICY, ::pbv1::FileDescriptor::FD_TYPE_NETPOLICY},
    {10 /* PROX_FDTYPE_CHANNEL */, ::pbv1::FileDescriptor::FD_TYPE_CHANNEL},
    {11 /* PROX_FDTYPE_NEXUS */, ::pbv1::FileDescriptor::FD_TYPE_NEXUS},
  };

  for (const auto &kv : fdtypeToEnumType) {
    XCTAssertEqual(GetFileDescriptorType(kv.first), kv.second, @"Bad fd type name for fdtype: %u",
                   kv.first);
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

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_EXEC
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.exec.target = &procTarget;
                    esMsg->event.exec.cwd = &fileCwd;
                    esMsg->event.exec.script = &fileScript;

                    // For version 5, simulate a "truncated" set of FDs
                    if (esMsg->version == 5) {
                      esMsg->event.exec.last_fd = 123;
                    } else {
                      esMsg->event.exec.last_fd = 3;
                    }

                    EXPECT_CALL(*mockESApi, ExecArgCount).WillOnce(testing::Return(3));
                    EXPECT_CALL(*mockESApi, ExecArg)
                      .WillOnce(testing::Return(MakeESStringToken("exec_path")))
                      .WillOnce(testing::Return(MakeESStringToken("-l")))
                      .WillOnce(testing::Return(MakeESStringToken("--foo")));

                    EXPECT_CALL(*mockESApi, ExecEnvCount).WillOnce(testing::Return(2));
                    EXPECT_CALL(*mockESApi, ExecEnv)
                      .WillOnce(
                        testing::Return(MakeESStringToken("ENV_PATH=/path/to/bin:/and/another")))
                      .WillOnce(testing::Return(MakeESStringToken("DEBUG=1")));

                    if (esMsg->version >= 4) {
                      EXPECT_CALL(*mockESApi, ExecFDCount).WillOnce(testing::Return(3));
                      EXPECT_CALL(*mockESApi, ExecFD)
                        .WillOnce(testing::Return(&fd1))
                        .WillOnce(testing::Return(&fd2))
                        .WillOnce(testing::Return(&fd3));
                    }
                  }
                          json:NO];
}

- (void)testSerializeMessageExecJSON {
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

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_EXEC
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.exec.target = &procTarget;
                    esMsg->event.exec.cwd = &fileCwd;
                    esMsg->event.exec.script = &fileScript;

                    // For version 5, simulate a "truncated" set of FDs
                    if (esMsg->version == 5) {
                      esMsg->event.exec.last_fd = 123;
                    } else {
                      esMsg->event.exec.last_fd = 3;
                    }

                    EXPECT_CALL(*mockESApi, ExecArgCount).WillOnce(testing::Return(3));
                    EXPECT_CALL(*mockESApi, ExecArg)
                      .WillOnce(testing::Return(MakeESStringToken("exec_path")))
                      .WillOnce(testing::Return(MakeESStringToken("-l")))
                      .WillOnce(testing::Return(MakeESStringToken("--foo")));

                    EXPECT_CALL(*mockESApi, ExecEnvCount).WillOnce(testing::Return(2));
                    EXPECT_CALL(*mockESApi, ExecEnv)
                      .WillOnce(
                        testing::Return(MakeESStringToken("ENV_PATH=/path/to/bin:/and/another")))
                      .WillOnce(testing::Return(MakeESStringToken("DEBUG=1")));

                    if (esMsg->version >= 4) {
                      EXPECT_CALL(*mockESApi, ExecFDCount).WillOnce(testing::Return(3));
                      EXPECT_CALL(*mockESApi, ExecFD)
                        .WillOnce(testing::Return(&fd1))
                        .WillOnce(testing::Return(&fd2))
                        .WillOnce(testing::Return(&fd3));
                    }
                  }
                          json:YES];
}

- (void)testEncodeEntitlements {
  int kMaxEncodeObjectEntries = 64;  // From Protobuf.mm
  // Test basic encoding without filtered entitlements
  {
    ::pbv1::Execution pbExec;

    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
    cd.entitlements = @{@"com.google.test" : @(YES)};

    XCTAssertEqual(0, pbExec.entitlement_info().entitlements_size());
    XCTAssertFalse(cd.entitlementsFiltered);
    XCTAssertEqual(1, cd.entitlements.count);

    EncodeEntitlements(&pbExec, cd);

    XCTAssertEqual(1, pbExec.entitlement_info().entitlements_size());
    XCTAssertTrue(pbExec.entitlement_info().has_entitlements_filtered());
    XCTAssertFalse(pbExec.entitlement_info().entitlements_filtered());
  }

  // Test basic encoding with filtered entitlements
  {
    ::pbv1::Execution pbExec;

    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
    cd.entitlements = @{@"com.google.test" : @(YES), @"com.google.test2" : @(NO)};
    cd.entitlementsFiltered = YES;

    XCTAssertEqual(0, pbExec.entitlement_info().entitlements_size());
    XCTAssertTrue(cd.entitlementsFiltered);
    XCTAssertEqual(2, cd.entitlements.count);

    EncodeEntitlements(&pbExec, cd);

    XCTAssertEqual(2, pbExec.entitlement_info().entitlements_size());
    XCTAssertTrue(pbExec.entitlement_info().has_entitlements_filtered());
    XCTAssertTrue(pbExec.entitlement_info().entitlements_filtered());
  }

  // Test max number of entitlements logged
  // When entitlements are clipped, `entitlements_filtered` is set to true
  {
    ::pbv1::Execution pbExec;
    NSMutableDictionary *ents = [NSMutableDictionary dictionary];

    for (int i = 0; i < 100; i++) {
      ents[[NSString stringWithFormat:@"k%d", i]] = @(i);
    }

    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
    cd.entitlements = ents;

    XCTAssertEqual(0, pbExec.entitlement_info().entitlements_size());
    XCTAssertFalse(cd.entitlementsFiltered);
    XCTAssertGreaterThan(cd.entitlements.count, kMaxEncodeObjectEntries);

    EncodeEntitlements(&pbExec, cd);

    XCTAssertEqual(kMaxEncodeObjectEntries, pbExec.entitlement_info().entitlements_size());
    XCTAssertTrue(pbExec.entitlement_info().has_entitlements_filtered());
    XCTAssertTrue(pbExec.entitlement_info().entitlements_filtered());
  }
}

- (void)testSerializeMessageExit {
  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_EXIT
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.exit.stat = W_EXITCODE(1, 0);
                  }
                          json:NO];
}

- (void)testEncodeExitStatus {
  {
    ::pbv1::Exit pbExit;
    EncodeExitStatus(&pbExit, W_EXITCODE(1, 0));
    XCTAssertTrue(pbExit.has_exited());
    XCTAssertEqual(1, pbExit.exited().exit_status());
  }

  {
    ::pbv1::Exit pbExit;
    EncodeExitStatus(&pbExit, W_EXITCODE(2, SIGUSR1));
    XCTAssertTrue(pbExit.has_signaled());
    XCTAssertEqual(SIGUSR1, pbExit.signaled().signal());
  }

  {
    ::pbv1::Exit pbExit;
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

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_FORK
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.fork.child = &procChild;
                  }
                          json:NO];
}

- (void)testSerializeMessageLink {
  __block es_file_t fileSource = MakeESFile("source", MakeStat(300));
  __block es_file_t fileTargetDir = MakeESFile("target_dir");
  es_string_token_t targetTok = MakeESStringToken("target_file");

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_LINK
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.link.source = &fileSource;
                    esMsg->event.link.target_dir = &fileTargetDir;
                    esMsg->event.link.target_filename = targetTok;
                  }
                          json:NO];
}

- (void)testSerializeMessageRename {
  __block es_file_t fileSource = MakeESFile("source", MakeStat(300));
  __block es_file_t fileTargetDir = MakeESFile("target_dir");
  es_string_token_t targetTok = MakeESStringToken("target_file");

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_RENAME
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
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
                  }
                          json:NO];
}

- (void)testSerializeMessageUnlink {
  __block es_file_t fileTarget = MakeESFile("unlink_file", MakeStat(300));
  __block es_file_t fileTargetParent = MakeESFile("unlink_file_parent", MakeStat(400));

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_UNLINK
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.unlink.target = &fileTarget;
                    esMsg->event.unlink.parent_dir = &fileTargetParent;
                  }
                          json:NO];
}

- (void)testSerializeMessageCodesigningInvalidated {
  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                  }
                          json:NO];
}

#if HAVE_MACOS_13

- (void)testSerializeMessageLoginWindowSessionLogin {
  __block es_event_lw_session_login_t lwLogin = {
    .username = MakeESStringToken("daemon"),
    .graphical_session_id = 123,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.lw_session_login = &lwLogin;
                  }];
}

- (void)testSerializeMessageLoginWindowSessionLogout {
  __block es_event_lw_session_logout_t lwLogout = {
    .username = MakeESStringToken("daemon"),
    .graphical_session_id = 123,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.lw_session_logout = &lwLogout;
                  }];
}

- (void)testSerializeMessageLoginWindowSessionLock {
  __block es_event_lw_session_lock_t lwLock = {
    .username = MakeESStringToken("daemon"),
    .graphical_session_id = 123,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.lw_session_lock = &lwLock;
                  }];
}

- (void)testSerializeMessageLoginWindowSessionUnlock {
  __block es_event_lw_session_unlock_t lwUnlock = {
    .username = MakeESStringToken("daemon"),
    .graphical_session_id = 123,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.lw_session_unlock = &lwUnlock;
                  }];
}

- (void)testSerializeMessageScreensharingAttach {
  __block es_event_screensharing_attach_t attach = {
    .success = true,
    .source_address_type = ES_ADDRESS_TYPE_IPV6,
    .source_address = MakeESStringToken("::1"),
    .viewer_appleid = MakeESStringToken("foo@example.com"),
    .authentication_type = MakeESStringToken("idk"),
    .authentication_username = MakeESStringToken("my_auth_user"),
    .session_username = MakeESStringToken("my_session_user"),
    .existing_session = true,
    .graphical_session_id = 123,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.screensharing_attach = &attach;
                  }];

  attach.source_address_type = (es_address_type_t)1234;
  attach.source_address = MakeESStringToken(NULL);
  attach.viewer_appleid = MakeESStringToken(NULL);
  attach.authentication_type = MakeESStringToken(NULL);
  attach.authentication_username = MakeESStringToken(NULL);
  attach.session_username = MakeESStringToken(NULL);

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.screensharing_attach = &attach;
                  }
                       variant:@"unset_fields"];
}

- (void)testSerializeMessageScreensharingDetach {
  __block es_event_screensharing_detach_t detach = {
    .source_address_type = ES_ADDRESS_TYPE_IPV4,
    .source_address = MakeESStringToken("1.2.3.4"),
    .viewer_appleid = MakeESStringToken("foo@example.com"),
    .graphical_session_id = 123,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.screensharing_detach = &detach;
                  }];
}

- (void)testSerializeMessageOpenSSHLogin {
  __block es_event_openssh_login_t sshLogin = {.success = true,
                                               .result_type = ES_OPENSSH_AUTH_SUCCESS,
                                               .source_address_type = ES_ADDRESS_TYPE_IPV4,
                                               .source_address = MakeESStringToken("1.2.3.4"),
                                               .username = MakeESStringToken("foo_user"),
                                               .has_uid = true,
                                               .uid = {
                                                 .uid = 12345,
                                               }};

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.openssh_login = &sshLogin;
                  }];

  sshLogin.success = false;
  sshLogin.result_type = ES_OPENSSH_AUTH_FAIL_HOSTBASED;
  sshLogin.source_address_type = ES_ADDRESS_TYPE_IPV6;
  sshLogin.source_address = MakeESStringToken("::1");
  sshLogin.has_uid = false;
  sshLogin.username = MakeESStringToken(NULL);

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.openssh_login = &sshLogin;
                  }
                       variant:@"failed_attempt"];
}

- (void)testSerializeMessageOpenSSHLogout {
  __block es_event_openssh_logout_t sshLogout = {
    .source_address_type = ES_ADDRESS_TYPE_IPV4,
    .source_address = MakeESStringToken("1.2.3.4"),
    .username = MakeESStringToken("foo_user"),
    .uid = 12345,
  };

  [self serializeAndCheckEvent:ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT
                  messageSetup:^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi,
                                 es_message_t *esMsg) {
                    esMsg->event.openssh_logout = &sshLogout;
                  }];
}

- (void)testGetSocketAddressType {
  std::map<es_address_type_t, ::pbv1::SocketAddress::Type> esToSantaAddrType = {
    {ES_ADDRESS_TYPE_NONE, ::pbv1::SocketAddress::TYPE_NONE},
    {ES_ADDRESS_TYPE_IPV4, ::pbv1::SocketAddress::TYPE_IPV4},
    {ES_ADDRESS_TYPE_IPV6, ::pbv1::SocketAddress::TYPE_IPV6},
    {ES_ADDRESS_TYPE_NAMED_SOCKET, ::pbv1::SocketAddress::TYPE_NAMED_SOCKET},
    {(es_address_type_t)1234, ::pbv1::SocketAddress::TYPE_UNKNOWN},
  };

  for (const auto &kv : esToSantaAddrType) {
    XCTAssertEqual(GetSocketAddressType(kv.first), kv.second);
  }
}

- (void)testGetOpenSSHLoginResultType {
  std::map<es_openssh_login_result_type_t, ::pbv1::OpenSSHLogin::Result> esToSantaOpenSSHResultType{
    {ES_OPENSSH_LOGIN_EXCEED_MAXTRIES, ::pbv1::OpenSSHLogin::RESULT_LOGIN_EXCEED_MAXTRIES},
    {ES_OPENSSH_LOGIN_ROOT_DENIED, ::pbv1::OpenSSHLogin::RESULT_LOGIN_ROOT_DENIED},
    {ES_OPENSSH_AUTH_SUCCESS, ::pbv1::OpenSSHLogin::RESULT_AUTH_SUCCESS},
    {ES_OPENSSH_AUTH_FAIL_NONE, ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_NONE},
    {ES_OPENSSH_AUTH_FAIL_PASSWD, ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_PASSWD},
    {ES_OPENSSH_AUTH_FAIL_KBDINT, ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_KBDINT},
    {ES_OPENSSH_AUTH_FAIL_PUBKEY, ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_PUBKEY},
    {ES_OPENSSH_AUTH_FAIL_HOSTBASED, ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_HOSTBASED},
    {ES_OPENSSH_AUTH_FAIL_GSSAPI, ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_GSSAPI},
    {ES_OPENSSH_INVALID_USER, ::pbv1::OpenSSHLogin::RESULT_INVALID_USER},
    {(es_openssh_login_result_type_t)1234, ::pbv1::OpenSSHLogin::RESULT_UNKNOWN},
  };

  for (const auto &kv : esToSantaOpenSSHResultType) {
    XCTAssertEqual(GetOpenSSHLoginResultType(kv.first), kv.second);
  }
}

#endif

- (void)testGetAccessType {
  std::map<es_event_type_t, ::pbv1::FileAccess::AccessType> eventTypeToAccessType = {
    {ES_EVENT_TYPE_AUTH_CLONE, ::pbv1::FileAccess::ACCESS_TYPE_CLONE},
    {ES_EVENT_TYPE_AUTH_COPYFILE, ::pbv1::FileAccess::ACCESS_TYPE_COPYFILE},
    {ES_EVENT_TYPE_AUTH_CREATE, ::pbv1::FileAccess::ACCESS_TYPE_CREATE},
    {ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ::pbv1::FileAccess::ACCESS_TYPE_EXCHANGEDATA},
    {ES_EVENT_TYPE_AUTH_LINK, ::pbv1::FileAccess::ACCESS_TYPE_LINK},
    {ES_EVENT_TYPE_AUTH_OPEN, ::pbv1::FileAccess::ACCESS_TYPE_OPEN},
    {ES_EVENT_TYPE_AUTH_RENAME, ::pbv1::FileAccess::ACCESS_TYPE_RENAME},
    {ES_EVENT_TYPE_AUTH_TRUNCATE, ::pbv1::FileAccess::ACCESS_TYPE_TRUNCATE},
    {ES_EVENT_TYPE_AUTH_UNLINK, ::pbv1::FileAccess::ACCESS_TYPE_UNLINK},
    {(es_event_type_t)1234, ::pbv1::FileAccess::ACCESS_TYPE_UNKNOWN},
  };

  for (const auto &kv : eventTypeToAccessType) {
    XCTAssertEqual(GetAccessType(kv.first), kv.second);
  }
}

- (void)testGetPolicyDecision {
  std::map<FileAccessPolicyDecision, ::pbv1::FileAccess::PolicyDecision> policyDecisionEnumToProto =
    {
      {FileAccessPolicyDecision::kNoPolicy, ::pbv1::FileAccess::POLICY_DECISION_UNKNOWN},
      {FileAccessPolicyDecision::kDenied, ::pbv1::FileAccess::POLICY_DECISION_DENIED},
      {FileAccessPolicyDecision::kDeniedInvalidSignature,
       ::pbv1::FileAccess::POLICY_DECISION_DENIED_INVALID_SIGNATURE},
      {FileAccessPolicyDecision::kAllowed, ::pbv1::FileAccess::POLICY_DECISION_UNKNOWN},
      {FileAccessPolicyDecision::kAllowedReadAccess, ::pbv1::FileAccess::POLICY_DECISION_UNKNOWN},
      {FileAccessPolicyDecision::kAllowedAuditOnly,
       ::pbv1::FileAccess::POLICY_DECISION_ALLOWED_AUDIT_ONLY},
      {(FileAccessPolicyDecision)1234, ::pbv1::FileAccess::POLICY_DECISION_UNKNOWN},
  };

  for (const auto &kv : policyDecisionEnumToProto) {
    XCTAssertEqual(GetPolicyDecision(kv.first), kv.second);
  }
}

- (void)testSerializeFileAccess {
  __block es_file_t openFile = MakeESFile("open_file", MakeStat(300));
  SerializeAndCheckNonESEvents(
    6, ES_EVENT_TYPE_AUTH_OPEN, @"file_access.json",
    ^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi, es_message_t *esMsg) {
      esMsg->event.open.file = &openFile;
    },
    ^std::vector<uint8_t>(std::shared_ptr<Serializer> serializer, const Message &msg) {
      return serializer->SerializeFileAccess("policy_version", "policy_name", msg,
                                             Enricher().Enrich(*msg->process), "target",
                                             FileAccessPolicyDecision::kDenied);
    });
}

- (void)testSerializeAllowlist {
  __block es_file_t closeFile = MakeESFile("close_file", MakeStat(300));
  SerializeAndCheckNonESEvents(
    1, ES_EVENT_TYPE_NOTIFY_CLOSE, @"allowlist.json",
    ^(std::shared_ptr<MockEndpointSecurityAPI> mockESApi, es_message_t *esMsg) {
      esMsg->event.close.target = &closeFile;
    },
    ^std::vector<uint8_t>(std::shared_ptr<Serializer> serializer, const Message &msg) {
      return serializer->SerializeAllowlist(msg, "hash_value");
    });
}

- (void)testSerializeBundleHashingEvent {
  SNTStoredEvent *se = [[SNTStoredEvent alloc] init];

  se.fileSHA256 = @"file_hash";
  se.fileBundleHash = @"file_bundle_hash";
  se.fileBundleName = @"file_bundle_name";
  se.fileBundleID = nil;
  se.fileBundlePath = @"file_bundle_path";
  se.filePath = @"file_path";

  std::vector<uint8_t> vec = Protobuf::Create(nullptr, nil)->SerializeBundleHashingEvent(se);
  std::string protoStr(vec.begin(), vec.end());

  ::pbv1::SantaMessage santaMsg;
  XCTAssertTrue(santaMsg.ParseFromString(protoStr));
  XCTAssertTrue(santaMsg.has_bundle());

  const ::pbv1::Bundle &pbBundle = santaMsg.bundle();

  ::pbv1::Hash pbHash = pbBundle.file_hash();
  XCTAssertEqualObjects(@(pbHash.hash().c_str()), se.fileSHA256);
  XCTAssertEqual(pbHash.type(), ::pbv1::Hash::HASH_ALGO_SHA256);

  pbHash = pbBundle.bundle_hash();
  XCTAssertEqualObjects(@(pbHash.hash().c_str()), se.fileBundleHash);
  XCTAssertEqual(pbHash.type(), ::pbv1::Hash::HASH_ALGO_SHA256);

  XCTAssertEqualObjects(@(pbBundle.bundle_name().c_str()), se.fileBundleName);
  XCTAssertEqualObjects(@(pbBundle.bundle_id().c_str()), @"");
  XCTAssertEqualObjects(@(pbBundle.bundle_path().c_str()), se.fileBundlePath);
  XCTAssertEqualObjects(@(pbBundle.path().c_str()), se.filePath);
}

- (void)testSerializeDiskAppeared {
  NSDictionary *props = @{
    @"DADevicePath" : @"",
    @"DADeviceVendor" : @"vendor",
    @"DADeviceModel" : @"model",
    @"DAAppearanceTime" : @(123456789),
    @"DAVolumePath" : [NSURL URLWithString:@"/"],
    @"DAMediaBSDName" : @"bsd",
    @"DAVolumeKind" : @"apfs",
    @"DADeviceProtocol" : @"usb",
  };

  std::vector<uint8_t> vec = Protobuf::Create(nullptr, nil)->SerializeDiskAppeared(props);
  std::string protoStr(vec.begin(), vec.end());

  ::pbv1::SantaMessage santaMsg;
  XCTAssertTrue(santaMsg.ParseFromString(protoStr));
  XCTAssertTrue(santaMsg.has_disk());

  const ::pbv1::Disk &pbDisk = santaMsg.disk();

  XCTAssertEqual(pbDisk.action(), ::pbv1::Disk::ACTION_APPEARED);

  XCTAssertEqualObjects(@(pbDisk.mount().c_str()), [props[@"DAVolumePath"] path]);
  XCTAssertEqualObjects(@(pbDisk.volume().c_str()), @"");
  XCTAssertEqualObjects(@(pbDisk.bsd_name().c_str()), props[@"DAMediaBSDName"]);
  XCTAssertEqualObjects(@(pbDisk.fs().c_str()), props[@"DAVolumeKind"]);
  XCTAssertEqualObjects(@(pbDisk.model().c_str()), @"vendor model");
  XCTAssertEqualObjects(@(pbDisk.serial().c_str()), @"");
  XCTAssertEqualObjects(@(pbDisk.bus().c_str()), props[@"DADeviceProtocol"]);
  XCTAssertEqualObjects(@(pbDisk.dmg_path().c_str()), @"");
  XCTAssertCppStringBeginsWith(pbDisk.mount_from(), std::string("/"));

  // Note: `DAAppearanceTime` is treated as a reference time since 2001 and is converted to a
  // reference time of 1970. Skip the calculation in the test here, just ensure the value is set.
  XCTAssertGreaterThan(pbDisk.appearance().seconds(), 1);
}

- (void)testSerializeDiskDisppeared {
  NSDictionary *props = @{
    @"DADevicePath" : @"",
    @"DADeviceVendor" : @"vendor",
    @"DADeviceModel" : @"model",
    @"DAAppearanceTime" : @(123456789),
    @"DAVolumePath" : [NSURL URLWithString:@"path"],
    @"DAMediaBSDName" : @"bsd",
    @"DAVolumeKind" : @"apfs",
    @"DADeviceProtocol" : @"usb",
  };

  std::vector<uint8_t> vec = Protobuf::Create(nullptr, nil)->SerializeDiskDisappeared(props);
  std::string protoStr(vec.begin(), vec.end());

  ::pbv1::SantaMessage santaMsg;
  XCTAssertTrue(santaMsg.ParseFromString(protoStr));
  XCTAssertTrue(santaMsg.has_disk());

  const ::pbv1::Disk &pbDisk = santaMsg.disk();

  XCTAssertEqual(pbDisk.action(), ::pbv1::Disk::ACTION_DISAPPEARED);

  XCTAssertEqualObjects(@(pbDisk.mount().c_str()), [props[@"DAVolumePath"] path]);
  XCTAssertEqualObjects(@(pbDisk.volume().c_str()), @"");
  XCTAssertEqualObjects(@(pbDisk.bsd_name().c_str()), props[@"DAMediaBSDName"]);
  XCTAssertEqualObjects(@(pbDisk.fs().c_str()), props[@"DAVolumeKind"]);
  XCTAssertEqualObjects(@(pbDisk.model().c_str()), @"vendor model");
  XCTAssertEqualObjects(@(pbDisk.serial().c_str()), @"");
  XCTAssertEqualObjects(@(pbDisk.bus().c_str()), props[@"DADeviceProtocol"]);
  XCTAssertEqualObjects(@(pbDisk.dmg_path().c_str()), @"");

  // Note: `DAAppearanceTime` is treated as a reference time since 2001 and is converted to a
  // reference time of 1970. Skip the calculation in the test here, just ensure the value is set.
  XCTAssertGreaterThan(pbDisk.appearance().seconds(), 1);
}

@end
