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
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "Source/common/SNTCommonEnums.h"
#include "Source/common/TestUtils.h"
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

class LoggerPeer : public Logger {
public:
  // Make base class constructors visible
  using Logger::Logger;

  LoggerPeer(std::unique_ptr<Logger> l) : Logger(l->serializer_, l->writer_) {}

  std::shared_ptr<serializers::Serializer> Serializer() {
    return serializer_;
  }

  std::shared_ptr<writers::Writer> Writer() {
    return writer_;
  }
};

} // namespace santa::santad::event_providers

using santa::santad::logs::endpoint_security::LoggerPeer;

class MockSerializer : public Empty {
public:
  MOCK_METHOD(std::vector<uint8_t>,
      SerializeMessage,
      (const EnrichedClose& msg));

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

@interface LoggerTest : XCTestCase
@end

@implementation LoggerTest {
  std::shared_ptr<MockEndpointSecurityAPI> _mockESApi;
  std::shared_ptr<MockSerializer> _mockSerializer;
  std::shared_ptr<MockWriter> _mockWriter;
}

- (void)setUp {
  self->_mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  self->_mockSerializer = std::make_shared<MockSerializer>();
  self->_mockWriter = std::make_shared<MockWriter>();
}

- (void)testCreate {
  // Ensure that the factory method creates expected serializers/writers pairs
  // auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  XCTAssertEqual(nullptr,
                 Logger::Create(self->_mockESApi,
                                (SNTEventLogType)123,
                                @"/tmp"));

  auto logger = LoggerPeer(Logger::Create(self->_mockESApi,
                                          SNTEventLogTypeFilelog, @"/tmp/temppy"));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<BasicString>(logger.Serializer()));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<File>(logger.Writer()));

  logger = LoggerPeer(Logger::Create(self->_mockESApi,
                                     SNTEventLogTypeSyslog,
                                     @"/tmp/temppy"));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<BasicString>(logger.Serializer()));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Syslog>(logger.Writer()));

  logger = LoggerPeer(Logger::Create(self->_mockESApi,
                                     SNTEventLogTypeNull,
                                     @"/tmp/temppy"));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Empty>(logger.Serializer()));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Null>(logger.Writer()));
}

- (void)testLog {
  // Ensure all Logger::Log* methods call the serializer followed by the writer
  es_message_t msg;

  // Note: In this test, `RetainMessage` isn't setup to return anything. This
  // means that the underlying `es_msg_` in the `Message` object is NULL, and
  // therefore no call to `ReleaseMessage` is ever made (hence no expectations).
  // Because we don't need to operate on the es_msg_, this simplifies the test.
  EXPECT_CALL(*self->_mockESApi, RetainMessage(testing::_));

  auto enriched_msg = std::make_shared<EnrichedMessage>(
      EnrichedClose(
          Message(self->_mockESApi, &msg),
          EnrichedProcess(std::nullopt,
                          std::nullopt,
                          std::nullopt,
                          std::nullopt,
                          EnrichedFile(std::nullopt, std::nullopt, std::nullopt)),
          EnrichedFile(std::nullopt, std::nullopt, std::nullopt)));

  EXPECT_CALL(*self->_mockSerializer,
              SerializeMessage(testing::A<const EnrichedClose&>())).Times(1);
  EXPECT_CALL(*self->_mockWriter, Write(testing::_)).Times(1);

  Logger(self->_mockSerializer, self->_mockWriter).Log(enriched_msg);

  XCTBubbleMockVerifyAndClearExpectations(self->_mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(self->_mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(self->_mockWriter.get());
}

- (void)testLogAllowList {
  es_message_t msg;
  std::string_view hash = "this_is_my_test_hash";
  EXPECT_CALL(*self->_mockESApi, RetainMessage(testing::_));
  EXPECT_CALL(*self->_mockSerializer, SerializeAllowlist(testing::_, hash));
  EXPECT_CALL(*self->_mockWriter, Write(testing::_));

  Logger(self->_mockSerializer, self->_mockWriter).LogAllowlist(
      Message(self->_mockESApi, &msg), hash);

  XCTBubbleMockVerifyAndClearExpectations(self->_mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(self->_mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(self->_mockWriter.get());
}

- (void)testLogBundleHashingEvents {
  NSArray<id> *events = @[@"event1", @"event2", @"event3"];
  EXPECT_CALL(*self->_mockSerializer, SerializeBundleHashingEvent(testing::_))
        .Times((int)[events count]);
  EXPECT_CALL(*self->_mockWriter, Write(testing::_))
        .Times((int)[events count]);

  Logger(self->_mockSerializer, self->_mockWriter)
      .LogBundleHashingEvents(events);

  XCTBubbleMockVerifyAndClearExpectations(self->_mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(self->_mockWriter.get());
}

- (void)testLogDiskAppeared {
  EXPECT_CALL(*self->_mockSerializer, SerializeDiskAppeared(testing::_));
  EXPECT_CALL(*self->_mockWriter, Write(testing::_));

  Logger(self->_mockSerializer, self->_mockWriter)
      .LogDiskAppeared(@{@"key": @"value"});

  XCTBubbleMockVerifyAndClearExpectations(self->_mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(self->_mockWriter.get());
}

- (void)testLogDiskDisappeared {
  EXPECT_CALL(*self->_mockSerializer, SerializeDiskDisappeared(testing::_));
  EXPECT_CALL(*self->_mockWriter, Write(testing::_));

  Logger(self->_mockSerializer, self->_mockWriter)
      .LogDiskDisappeared(@{@"key": @"value"});

  XCTBubbleMockVerifyAndClearExpectations(self->_mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(self->_mockWriter.get());
}

@end
