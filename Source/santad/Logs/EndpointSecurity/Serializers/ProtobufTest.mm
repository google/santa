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
#include <sys/signal.h>
#include <sys/wait.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <time.h>
#include <uuid/uuid.h>

#include <google/protobuf/util/json_util.h>

#include "Source/common/TestUtils.h"
#include "Source/common/santa_new.pb.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Protobuf.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"

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
}

using santa::santad::logs::endpoint_security::serializers::EncodeExitStatus;

JsonPrintOptions DefaultJsonPrintOptions() {
  JsonPrintOptions options;
  options.always_print_enums_as_ints = false;
  options.always_print_primitive_fields = false;
  options.preserve_proto_field_names = true;
  options.add_whitespace = true;
  return options;
}

NSString *TestJsonPath(NSString *jsonFileName) {
  static dispatch_once_t onceToken;
  static NSString *testPath;
  static NSString *testDataRepoPath = @"santa/Source/santad/testdata/protobuf";

  dispatch_once(&onceToken, ^{
    testPath = [NSString pathWithComponents:@[
      [[[NSProcessInfo processInfo] environment] objectForKey:@"TEST_SRCDIR"], testDataRepoPath
    ]];
  });

  return [NSString pathWithComponents:@[ testPath, jsonFileName ]];
}

NSString *LoadTestJson(NSString *jsonFileName) {
  NSError *err = nil;
  NSString *jsonData = [NSString stringWithContentsOfFile:TestJsonPath(jsonFileName)
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

void CheckProto(const pb::SantaMessage &santaMsg, std::shared_ptr<EnrichedMessage> enrichedMsg,
                NSString *jsonFileName) {
  return std::visit(
    [santaMsg, jsonFileName](const EnrichedEventType &enrichedEvent) {
      CheckSantaMessage(santaMsg, enrichedEvent.es_msg(), enrichedEvent.uuid(),
                        enrichedEvent.enrichment_time());
      NSString *wantData = LoadTestJson(jsonFileName);
      std::string got = ConvertMessageToJsonString(santaMsg);

      XCTAssertEqualObjects([NSString stringWithUTF8String:got.c_str()], wantData);
    },
    enrichedMsg->GetEnrichedMessage());
}

void SerializeAndCheck(es_message_t *esMsg, NSString *jsonFileName) {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage(esMsg);

  std::shared_ptr<Serializer> bs = Protobuf::Create(mockESApi);
  std::shared_ptr<EnrichedMessage> enrichedMsg = Enricher().Enrich(Message(mockESApi, esMsg));

  std::vector<uint8_t> vec = bs->SerializeMessage(enrichedMsg);
  std::string protoStr(vec.begin(), vec.end());

  pb::SantaMessage santaMsg;
  XCTAssertTrue(santaMsg.ParseFromString(protoStr));

  CheckProto(santaMsg, enrichedMsg, jsonFileName);
}

@interface ProtobufTest : XCTestCase
@end

@implementation ProtobufTest

- (void)testSerializeMessageClose {
  es_file_t procFile = MakeESFile("foo", MakeStat(100));
  es_file_t ttyFile = MakeESFile("footty", MakeStat(200));
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_file_t file = MakeESFile("close_file", MakeStat(300));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &proc);
  esMsg.process->tty = &ttyFile;
  esMsg.event.close.modified = true;
  esMsg.event.close.target = &file;

  SerializeAndCheck(&esMsg, @"close.json");
}

- (void)testSerializeMessageExchange {
  es_file_t procFile = MakeESFile("foo", MakeStat(100));
  es_file_t ttyFile = MakeESFile("footty", MakeStat(200));
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_file_t file1 = MakeESFile("exchange_file_1", MakeStat(300));
  es_file_t file2 = MakeESFile("exchange_file_1", MakeStat(400));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, &proc);
  esMsg.process->tty = &ttyFile;
  esMsg.event.exchangedata.file1 = &file1;
  esMsg.event.exchangedata.file2 = &file2;

  SerializeAndCheck(&esMsg, @"exchangedata.json");
}

- (void)testSerializeMessageExit {
  es_file_t procFile = MakeESFile("foo", MakeStat(100));
  es_file_t ttyFile = MakeESFile("footty", MakeStat(200));
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);
  esMsg.process->tty = &ttyFile;
  esMsg.event.exit.stat = W_EXITCODE(1, 0);

  SerializeAndCheck(&esMsg, @"exit.json");
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
  es_file_t procFile = MakeESFile("foo", MakeStat(100));
  es_file_t procFileChild = MakeESFile("foo_child", MakeStat(200));
  es_file_t ttyFile = MakeESFile("footty", MakeStat(300));
  es_file_t ttyFileChild = MakeESFile("footty", MakeStat(400));
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_process_t procChild =
    MakeESProcess(&procFileChild, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_FORK, &proc);
  esMsg.process->tty = &ttyFile;
  esMsg.event.fork.child = &procChild;
  esMsg.event.fork.child->tty = &ttyFileChild;

  SerializeAndCheck(&esMsg, @"fork.json");
}

@end
