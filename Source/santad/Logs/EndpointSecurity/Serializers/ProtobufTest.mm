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
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
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
  NSString *jsonData = [NSString stringWithContentsOfFile:TestJsonPath(@"close.json")
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

void CheckProto(const pb::SantaMessage &santaMsg, const EnrichedClose &enrichedClose) {
  CheckSantaMessage(santaMsg, enrichedClose.es_msg(), enrichedClose.uuid(),
                    enrichedClose.enrichment_time());
  NSString *wantData = LoadTestJson(@"close.json");

  JsonPrintOptions options = DefaultJsonPrintOptions();
  std::string json;
  google::protobuf::util::MessageToJsonString(santaMsg.close(), &json, options);
  XCTAssertEqualObjects([NSString stringWithUTF8String:json.c_str()], wantData);
}

void CheckProto(const pb::SantaMessage &santaMsg, const EnrichedExchange &enrichedExchange) {}

void CheckProto(const pb::SantaMessage &santaMsg, const EnrichedExec &enrichedExec) {}

void CheckProto(const pb::SantaMessage &santaMsg, const EnrichedExit &enrichedExit) {}

void CheckProto(const pb::SantaMessage &santaMsg, const EnrichedFork &enrichedFork) {}

void CheckProto(const pb::SantaMessage &santaMsg, const EnrichedLink &enrichedLink) {}

void CheckProto(const pb::SantaMessage &santaMsg, const EnrichedRename &enrichedRename) {}

void CheckProto(const pb::SantaMessage &santaMsg, const EnrichedUnlink &enrichedUnlink) {}

void CheckProto(const pb::SantaMessage &santaMsg, std::shared_ptr<EnrichedMessage> enrichedMsg) {
  return std::visit([santaMsg](const auto &arg) { return CheckProto(santaMsg, arg); },
                    enrichedMsg->GetEnrichedMessage());
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

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage(&esMsg);

  std::shared_ptr<Serializer> bs = Protobuf::Create(mockESApi);

  std::shared_ptr<EnrichedMessage> enrichedClose = Enricher().Enrich(Message(mockESApi, &esMsg));
  std::vector<uint8_t> vec = bs->SerializeMessage(enrichedClose);
  std::string protoStr(vec.begin(), vec.end());

  pb::SantaMessage santaMsg;
  XCTAssertTrue(santaMsg.ParseFromString(protoStr));

  CheckProto(santaMsg, enrichedClose);
}

@end
