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

#include <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#import "Source/common/SNTCommonEnums.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Empty.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Protobuf.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/File.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Null.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Spool.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Syslog.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Writer.h"

using santa::santad::event_providers::endpoint_security::EnrichedClose;
using santa::santad::event_providers::endpoint_security::EnrichedFile;
using santa::santad::event_providers::endpoint_security::EnrichedMessage;
using santa::santad::event_providers::endpoint_security::EnrichedProcess;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::Logger;
using santa::santad::logs::endpoint_security::serializers::BasicString;
using santa::santad::logs::endpoint_security::serializers::Empty;
using santa::santad::logs::endpoint_security::serializers::Protobuf;
using santa::santad::logs::endpoint_security::writers::File;
using santa::santad::logs::endpoint_security::writers::Null;
using santa::santad::logs::endpoint_security::writers::Spool;
using santa::santad::logs::endpoint_security::writers::Syslog;

namespace santa::santad::logs::endpoint_security {

class LoggerPeer : public Logger {
 public:
  // Make base class constructors visible
  using Logger::Logger;

  LoggerPeer(std::unique_ptr<Logger> l) : Logger(l->serializer_, l->writer_) {}

  std::shared_ptr<serializers::Serializer> Serializer() { return serializer_; }

  std::shared_ptr<writers::Writer> Writer() { return writer_; }
};

}  // namespace santa::santad::logs::endpoint_security

using santa::santad::logs::endpoint_security::LoggerPeer;

class MockSerializer : public Empty {
 public:
  MOCK_METHOD(std::vector<uint8_t>, SerializeMessage, (const EnrichedClose &msg));

  MOCK_METHOD(std::vector<uint8_t>, SerializeAllowlist, (const Message &, const std::string_view));

  MOCK_METHOD(std::vector<uint8_t>, SerializeBundleHashingEvent, (SNTStoredEvent *));
  MOCK_METHOD(std::vector<uint8_t>, SerializeDiskAppeared, (NSDictionary *));
  MOCK_METHOD(std::vector<uint8_t>, SerializeDiskDisappeared, (NSDictionary *));

  MOCK_METHOD(
    std::vector<uint8_t>, SerializeFileAccess,
    (const std::string &policy_version, const std::string &policy_name,
     const santa::santad::event_providers::endpoint_security::Message &msg,
     const santa::santad::event_providers::endpoint_security::EnrichedProcess &enriched_process,
     const std::string &target, FileAccessPolicyDecision decision));
};

class MockWriter : public Null {
 public:
  MOCK_METHOD(void, Write, (std::vector<uint8_t> && bytes));
};

@interface LoggerTest : XCTestCase
@end

@implementation LoggerTest

- (void)testCreate {
  // Ensure that the factory method creates expected serializers/writers pairs
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  XCTAssertEqual(nullptr, Logger::Create(mockESApi, (SNTEventLogType)123, nil, @"/tmp/temppy",
                                         @"/tmp/spool", 1, 1, 1));

  LoggerPeer logger(
    Logger::Create(mockESApi, SNTEventLogTypeFilelog, nil, @"/tmp/temppy", @"/tmp/spool", 1, 1, 1));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<BasicString>(logger.Serializer()));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<File>(logger.Writer()));

  logger = LoggerPeer(
    Logger::Create(mockESApi, SNTEventLogTypeSyslog, nil, @"/tmp/temppy", @"/tmp/spool", 1, 1, 1));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<BasicString>(logger.Serializer()));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Syslog>(logger.Writer()));

  logger = LoggerPeer(
    Logger::Create(mockESApi, SNTEventLogTypeNull, nil, @"/tmp/temppy", @"/tmp/spool", 1, 1, 1));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Empty>(logger.Serializer()));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Null>(logger.Writer()));

  logger = LoggerPeer(Logger::Create(mockESApi, SNTEventLogTypeProtobuf, nil, @"/tmp/temppy",
                                     @"/tmp/spool", 1, 1, 1));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Protobuf>(logger.Serializer()));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Spool>(logger.Writer()));

  logger = LoggerPeer(
    Logger::Create(mockESApi, SNTEventLogTypeJSON, nil, @"/tmp/temppy", @"/tmp/spool", 1, 1, 1));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Protobuf>(logger.Serializer()));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<File>(logger.Writer()));
}

- (void)testLog {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  auto mockSerializer = std::make_shared<MockSerializer>();
  auto mockWriter = std::make_shared<MockWriter>();

  // Ensure all Logger::Log* methods call the serializer followed by the writer
  es_message_t msg;

  mockESApi->SetExpectationsRetainReleaseMessage();

  {
    auto enrichedMsg = std::make_unique<EnrichedMessage>(EnrichedClose(
      Message(mockESApi, &msg),
      EnrichedProcess(std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                      EnrichedFile(std::nullopt, std::nullopt, std::nullopt), std::nullopt),
      EnrichedFile(std::nullopt, std::nullopt, std::nullopt)));

    EXPECT_CALL(*mockSerializer, SerializeMessage(testing::A<const EnrichedClose &>())).Times(1);
    EXPECT_CALL(*mockWriter, Write).Times(1);

    Logger(mockSerializer, mockWriter).Log(std::move(enrichedMsg));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testLogAllowList {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  auto mockSerializer = std::make_shared<MockSerializer>();
  auto mockWriter = std::make_shared<MockWriter>();
  es_message_t msg;
  std::string_view hash = "this_is_my_test_hash";

  mockESApi->SetExpectationsRetainReleaseMessage();
  EXPECT_CALL(*mockSerializer, SerializeAllowlist(testing::_, hash));
  EXPECT_CALL(*mockWriter, Write);

  Logger(mockSerializer, mockWriter).LogAllowlist(Message(mockESApi, &msg), hash);

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testLogBundleHashingEvents {
  auto mockSerializer = std::make_shared<MockSerializer>();
  auto mockWriter = std::make_shared<MockWriter>();
  NSArray<id> *events = @[ @"event1", @"event2", @"event3" ];

  EXPECT_CALL(*mockSerializer, SerializeBundleHashingEvent).Times((int)[events count]);
  EXPECT_CALL(*mockWriter, Write).Times((int)[events count]);

  Logger(mockSerializer, mockWriter).LogBundleHashingEvents(events);

  XCTBubbleMockVerifyAndClearExpectations(mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testLogDiskAppeared {
  auto mockSerializer = std::make_shared<MockSerializer>();
  auto mockWriter = std::make_shared<MockWriter>();

  EXPECT_CALL(*mockSerializer, SerializeDiskAppeared);
  EXPECT_CALL(*mockWriter, Write);

  Logger(mockSerializer, mockWriter).LogDiskAppeared(@{@"key" : @"value"});

  XCTBubbleMockVerifyAndClearExpectations(mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testLogDiskDisappeared {
  auto mockSerializer = std::make_shared<MockSerializer>();
  auto mockWriter = std::make_shared<MockWriter>();

  EXPECT_CALL(*mockSerializer, SerializeDiskDisappeared);
  EXPECT_CALL(*mockWriter, Write);

  Logger(mockSerializer, mockWriter).LogDiskDisappeared(@{@"key" : @"value"});

  XCTBubbleMockVerifyAndClearExpectations(mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testLogFileAccess {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  auto mockSerializer = std::make_shared<MockSerializer>();
  auto mockWriter = std::make_shared<MockWriter>();
  es_message_t msg;

  mockESApi->SetExpectationsRetainReleaseMessage();
  EXPECT_CALL(*mockSerializer, SerializeFileAccess);
  EXPECT_CALL(*mockWriter, Write);

  Logger(mockSerializer, mockWriter)
    .LogFileAccess(
      "v1", "name", Message(mockESApi, &msg),
      EnrichedProcess(std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                      EnrichedFile(std::nullopt, std::nullopt, std::nullopt), std::nullopt),
      "tgt", FileAccessPolicyDecision::kDenied);

  XCTBubbleMockVerifyAndClearExpectations(mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

@end
