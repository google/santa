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

// #include <EndpointSecurity/EndpointSecurity.h>
#include <Foundation/Foundation.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "Source/common/SNTCommonEnums.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Empty.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/File.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Null.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Syslog.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Writer.h"
#include "gmock/gmock.h"

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::EnrichedMessage;
using santa::santad::event_providers::endpoint_security::EnrichedClose;
using santa::santad::event_providers::endpoint_security::EnrichedProcess;
using santa::santad::event_providers::endpoint_security::EnrichedFile;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::Logger;
using santa::santad::logs::endpoint_security::serializers::BasicString;
using santa::santad::logs::endpoint_security::serializers::Empty;
using santa::santad::logs::endpoint_security::writers::File;
using santa::santad::logs::endpoint_security::writers::Null;
using santa::santad::logs::endpoint_security::writers::Syslog;

namespace santa::santad::logs::endpoint_security {

class LoggerTest : public Logger {
public:
  // Make base class constructors visible
  using Logger::Logger;

  LoggerTest(std::unique_ptr<Logger> l) : Logger(l->serializer_, l->writer_) {}

  std::shared_ptr<serializers::Serializer> Serializer() {
    return serializer_;
  }

  std::shared_ptr<writers::Writer> Writer() {
    return writer_;
  }
};

} // namespace santa::santad::event_providers

using santa::santad::logs::endpoint_security::LoggerTest;

class MockSerializer : public Empty {
public:
  MOCK_METHOD(std::vector<uint8_t>, SerializeMessage, (const EnrichedClose& msg));

  MOCK_METHOD(std::vector<uint8_t>,
      SerializeAllowlist,
      (const Message&, const std::string_view));

  MOCK_METHOD(std::vector<uint8_t>, SerializeBundleHashingEvent, (SNTStoredEvent*));
  MOCK_METHOD(std::vector<uint8_t>, SerializeDiskAppeared, (NSDictionary*));
  MOCK_METHOD(std::vector<uint8_t>, SerializeDiskDisappeared, (NSDictionary*));
};

class MockWriter : public Null {
public:
  MOCK_METHOD(void, Write, (std::vector<uint8_t>&& bytes));
};

class MockEndpointSecurityAPI : public EndpointSecurityAPI {
public:
  MOCK_METHOD(es_message_t*, RetainMessage, (const es_message_t* msg));
  MOCK_METHOD(void, ReleaseMessage, (es_message_t* msg));
};

TEST(Logger, Create) {
  // Ensure that the factory method creates expected serializers/writers pairs

  // Note: The EXIT test must come first otherwise googletest complains about
  // additional threads existing before forking.
  EXPECT_EXIT(Logger::Create(nullptr, (SNTEventLogType)123, @"/tmp/temppy"),
              testing::ExitedWithCode(EXIT_FAILURE),
              ".*");

  auto mock_esapi = std::make_shared<MockEndpointSecurityAPI>();
  auto logger = LoggerTest(Logger::Create(mock_esapi,
                                          SNTEventLogTypeFilelog, @"/tmp/temppy"));
  EXPECT_NE(std::dynamic_pointer_cast<BasicString>(logger.Serializer()), nullptr);
  EXPECT_NE(std::dynamic_pointer_cast<File>(logger.Writer()), nullptr);

  logger = LoggerTest(Logger::Create(mock_esapi,
                                     SNTEventLogTypeSyslog,
                                     @"/tmp/temppy"));
  EXPECT_NE(std::dynamic_pointer_cast<BasicString>(logger.Serializer()), nullptr);
  EXPECT_NE(std::dynamic_pointer_cast<Syslog>(logger.Writer()), nullptr);

  logger = LoggerTest(Logger::Create(mock_esapi,
                                     SNTEventLogTypeNull,
                                     @"/tmp/temppy"));
  EXPECT_NE(std::dynamic_pointer_cast<Empty>(logger.Serializer()), nullptr);
  EXPECT_NE(std::dynamic_pointer_cast<Null>(logger.Writer()), nullptr);
}

TEST(Logger, SerializeAndWrite) {
  // Ensure all Logger::Log* methods call the serializer followed by the writer

  auto mock_esapi = std::make_shared<MockEndpointSecurityAPI>();
  es_message_t msg;

  // Note: In this test, `RetainMessage` isn't setup to return anything. This
  // means that the underlying `es_msg_` in the `Message` object is NULL, and
  // therefore no call to `ReleaseMessage` is ever made (hence no expectations).
  EXPECT_CALL(*mock_esapi, RetainMessage(testing::_));

  auto enriched_msg = std::make_shared<EnrichedMessage>(
      EnrichedClose(
          Message(mock_esapi, &msg),
          EnrichedProcess(std::nullopt,
                          std::nullopt,
                          std::nullopt,
                          std::nullopt,
                          EnrichedFile(std::nullopt, std::nullopt, std::nullopt)),
          EnrichedFile(std::nullopt, std::nullopt, std::nullopt)));

  auto mock_serializer = std::make_shared<MockSerializer>();
  auto mock_writer = std::make_shared<MockWriter>();
  auto logger = Logger(mock_serializer, mock_writer);

  // Log(...)
  EXPECT_CALL(*mock_serializer,
              SerializeMessage(testing::A<const EnrichedClose&>())).Times(1);
  EXPECT_CALL(*mock_writer, Write(testing::_)).Times(1);

  logger.Log(enriched_msg);

  testing::Mock::VerifyAndClearExpectations(mock_esapi.get());

  // LogAllowlist(...)
  std::string_view test_hash = "this_is_my_test_hash";
  EXPECT_CALL(*mock_esapi, RetainMessage(testing::_));
  EXPECT_CALL(*mock_serializer, SerializeAllowlist(testing::_, test_hash));
  EXPECT_CALL(*mock_writer, Write(testing::_));

  logger.LogAllowlist(Message(mock_esapi, &msg), test_hash);

  testing::Mock::VerifyAndClearExpectations(mock_esapi.get());

  // void LogBundleHashingEvents(...)
  NSArray<id> *events = @[@"event1", @"event2", @"event3"];
  EXPECT_CALL(*mock_serializer, SerializeBundleHashingEvent(testing::_))
      .Times((int)[events count]);
  EXPECT_CALL(*mock_writer, Write(testing::_))
      .Times((int)[events count]);
  logger.LogBundleHashingEvents(events);

  testing::Mock::VerifyAndClearExpectations(mock_esapi.get());

  // LogDiskAppeared(...)
  EXPECT_CALL(*mock_serializer, SerializeDiskAppeared(testing::_));
  EXPECT_CALL(*mock_writer, Write(testing::_));
  logger.LogDiskAppeared(@{@"key": @"value"});

  testing::Mock::VerifyAndClearExpectations(mock_esapi.get());

  // LogDiskDisappeared(...)
  EXPECT_CALL(*mock_serializer, SerializeDiskDisappeared(testing::_));
  EXPECT_CALL(*mock_writer, Write(testing::_));
  logger.LogDiskDisappeared(@{@"key": @"value"});

  testing::Mock::VerifyAndClearExpectations(mock_esapi.get());
}
