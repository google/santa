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
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <objc/NSObjCRuntime.h>
#include <cstddef>

#include <memory>
#include <set>

#include "Source/common/PrefixTree.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/TestUtils.h"
#include "Source/common/Unit.h"
#import "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityRecorder.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/Metrics.h"
#import "Source/santad/SNTCompilerController.h"

using santa::common::PrefixTree;
using santa::common::Unit;
using santa::santad::EventDisposition;
using santa::santad::Processor;
using santa::santad::event_providers::AuthResultCache;
using santa::santad::event_providers::endpoint_security::EnrichedMessage;
using santa::santad::event_providers::endpoint_security::Enricher;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::Logger;

class MockEnricher : public Enricher {
 public:
  MOCK_METHOD(std::unique_ptr<EnrichedMessage>, Enrich, (Message &&));
};

class MockAuthResultCache : public AuthResultCache {
 public:
  using AuthResultCache::AuthResultCache;

  MOCK_METHOD(void, RemoveFromCache, (const es_file_t *));
};

class MockLogger : public Logger {
 public:
  using Logger::Logger;

  MOCK_METHOD(void, Log, (std::unique_ptr<EnrichedMessage>));
};

@interface SNTEndpointSecurityRecorderTest : XCTestCase
@property id mockConfigurator;
@end

@implementation SNTEndpointSecurityRecorderTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  NSString *testPattern = @"^/foo/match.*";
  NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:testPattern
                                                                      options:0
                                                                        error:NULL];
  OCMStub([self.mockConfigurator fileChangesRegex]).andReturn(re);
}

- (void)testEnable {
  // Ensure the client subscribes to expected event types
  std::set<es_event_type_t> expectedEventSubs{
    ES_EVENT_TYPE_NOTIFY_CLOSE,  ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, ES_EVENT_TYPE_NOTIFY_EXEC,
    ES_EVENT_TYPE_NOTIFY_FORK,   ES_EVENT_TYPE_NOTIFY_EXIT,         ES_EVENT_TYPE_NOTIFY_LINK,
    ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_UNLINK,
  };
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  id recorderClient = [[SNTEndpointSecurityRecorder alloc] initWithESAPI:mockESApi
                                                                 metrics:nullptr
                                                               processor:Processor::kRecorder];

  EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs)).WillOnce(testing::Return(true));

  [recorderClient enable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

typedef void (^testHelperBlock)(es_message_t *message,
                                std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
                                SNTEndpointSecurityRecorder *recorderClient,
                                std::shared_ptr<PrefixTree<Unit>> prefixTree,
                                dispatch_semaphore_t *sema, dispatch_semaphore_t *semaMetrics);

es_file_t targetFileMatchesRegex = MakeESFile("/foo/matches");
es_file_t targetFileMissesRegex = MakeESFile("/foo/misses");

- (void)testHandleMessageWithMatchCalls:(NSUInteger)regexMatchCalls
                          withMissCalls:(NSUInteger)regexFailsMatchCalls
                              withBlock:(testHelperBlock)testBlock {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &proc, ActionType::Auth);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  std::unique_ptr<EnrichedMessage> enrichedMsg = std::unique_ptr<EnrichedMessage>(nullptr);

  auto mockEnricher = std::make_shared<MockEnricher>();

  if (regexMatchCalls > 0) {
    EXPECT_CALL(*mockEnricher, Enrich).WillOnce(testing::Return(std::move(enrichedMsg)));
  }

  auto mockAuthCache = std::make_shared<MockAuthResultCache>(nullptr, nil);
  EXPECT_CALL(*mockAuthCache, RemoveFromCache(&targetFileMatchesRegex)).Times((int)regexMatchCalls);
  EXPECT_CALL(*mockAuthCache, RemoveFromCache(&targetFileMissesRegex))
    .Times((int)regexFailsMatchCalls);

  dispatch_semaphore_t semaMetrics = dispatch_semaphore_create(0);

  // NOTE: Currently unable to create a partial mock of the
  // `SNTEndpointSecurityRecorder` object. There is a bug in OCMock that doesn't
  // properly handle the `processEnrichedMessage:handler:` block. Instead this
  // test will mock the `Log` method that is called in the handler block.
  __block dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  auto mockLogger = std::make_shared<MockLogger>(nullptr, nullptr);
  if (regexMatchCalls > 0) {
    EXPECT_CALL(*mockLogger, Log).WillOnce(testing::InvokeWithoutArgs(^() {
      dispatch_semaphore_signal(sema);
    }));
  }

  auto prefixTree = std::make_shared<PrefixTree<Unit>>();

  id mockCC = OCMStrictClassMock([SNTCompilerController class]);

  SNTEndpointSecurityRecorder *recorderClient =
    [[SNTEndpointSecurityRecorder alloc] initWithESAPI:mockESApi
                                               metrics:nullptr
                                                logger:mockLogger
                                              enricher:mockEnricher
                                    compilerController:mockCC
                                       authResultCache:mockAuthCache
                                            prefixTree:prefixTree];

  testBlock(&esMsg, mockESApi, mockCC, recorderClient, prefixTree, &sema, &semaMetrics);

  XCTAssertTrue(OCMVerifyAll(mockCC));

  XCTBubbleMockVerifyAndClearExpectations(mockAuthCache.get());
  XCTBubbleMockVerifyAndClearExpectations(mockEnricher.get());
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockLogger.get());

  [mockCC stopMocking];
}

- (void)testHandleMessageWithCloseMappedWriteable {
  if (@available(macOS 13.0, *)) {
    // CLOSE not modified, but was_mapped_writable, should remove from cache,
    // and matches fileChangesRegex
    testHelperBlock testBlock =
      ^(es_message_t *esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
        SNTEndpointSecurityRecorder *recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
        __autoreleasing dispatch_semaphore_t *sema,
        __autoreleasing dispatch_semaphore_t *semaMetrics) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
        esMsg->event.close.modified = false;
        esMsg->event.close.was_mapped_writable = true;
        esMsg->event.close.target = &targetFileMatchesRegex;
        Message msg(mockESApi, esMsg);

        OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();

        XCTAssertNoThrow([recorderClient handleMessage:Message(mockESApi, esMsg)
                                    recordEventMetrics:^(EventDisposition d) {
                                      XCTAssertEqual(d, EventDisposition::kProcessed);
                                      dispatch_semaphore_signal(*semaMetrics);
                                    }]);
        XCTAssertSemaTrue(*semaMetrics, 5, "Metrics not recorded within expected window");
        XCTAssertSemaTrue(*sema, 5, "Log wasn't called within expected time window");
      };

    [self testHandleMessageWithMatchCalls:1 withMissCalls:0 withBlock:testBlock];
  }
}

- (void)testHandleEventCloseNotModifiedWithWasMappedWritable {
  if (@available(macOS 13.0, *)) {
    // CLOSE not modified, but was_mapped_writable, remove from cache, and does not match
    // fileChangesRegex
    testHelperBlock testBlock =
      ^(es_message_t *esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
        SNTEndpointSecurityRecorder *recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
        __autoreleasing dispatch_semaphore_t *sema,
        __autoreleasing dispatch_semaphore_t *semaMetrics) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
        esMsg->event.close.modified = false;
        esMsg->event.close.was_mapped_writable = true;
        esMsg->event.close.target = &targetFileMissesRegex;
        Message msg(mockESApi, esMsg);

        XCTAssertNoThrow([recorderClient handleMessage:Message(mockESApi, esMsg)
                                    recordEventMetrics:^(EventDisposition d) {
                                      XCTFail("Metrics record callback should not be called here");
                                    }]);
      };

    [self testHandleMessageWithMatchCalls:0 withMissCalls:1 withBlock:testBlock];
  }
}

- (void)testHandleMessage {
  // CLOSE not modified, bail early
  testHelperBlock testBlock = ^(
    es_message_t *esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
    SNTEndpointSecurityRecorder *recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
    __autoreleasing dispatch_semaphore_t *sema, __autoreleasing dispatch_semaphore_t *semaMetrics) {
    esMsg->event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
    esMsg->event.close.modified = false;
    esMsg->event.close.target = NULL;

    XCTAssertNoThrow([recorderClient handleMessage:Message(mockESApi, esMsg)
                                recordEventMetrics:^(EventDisposition d) {
                                  XCTFail("Metrics record callback should not be called here");
                                }]);
  };

  [self testHandleMessageWithMatchCalls:0 withMissCalls:0 withBlock:testBlock];

  // CLOSE modified, remove from cache, and matches fileChangesRegex
  testBlock = ^(
    es_message_t *esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
    SNTEndpointSecurityRecorder *recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
    __autoreleasing dispatch_semaphore_t *sema, __autoreleasing dispatch_semaphore_t *semaMetrics) {
    esMsg->event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
    esMsg->event.close.modified = true;
    esMsg->event.close.target = &targetFileMatchesRegex;
    Message msg(mockESApi, esMsg);

    OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();

    [recorderClient handleMessage:std::move(msg)
               recordEventMetrics:^(EventDisposition d) {
                 XCTAssertEqual(d, EventDisposition::kProcessed);
                 dispatch_semaphore_signal(*semaMetrics);
               }];

    XCTAssertSemaTrue(*semaMetrics, 5, "Metrics not recorded within expected window");
    XCTAssertSemaTrue(*sema, 5, "Log wasn't called within expected time window");
  };

  [self testHandleMessageWithMatchCalls:1 withMissCalls:0 withBlock:testBlock];

  // CLOSE modified, remove from cache, but doesn't match fileChangesRegex
  testBlock = ^(
    es_message_t *esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
    SNTEndpointSecurityRecorder *recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
    __autoreleasing dispatch_semaphore_t *sema, __autoreleasing dispatch_semaphore_t *semaMetrics) {
    esMsg->event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
    esMsg->event.close.modified = true;
    esMsg->event.close.target = &targetFileMissesRegex;
    Message msg(mockESApi, esMsg);
    XCTAssertNoThrow([recorderClient handleMessage:Message(mockESApi, esMsg)
                                recordEventMetrics:^(EventDisposition d) {
                                  XCTFail("Metrics record callback should not be called here");
                                }]);
  };

  [self testHandleMessageWithMatchCalls:0 withMissCalls:1 withBlock:testBlock];

  // LINK, Prefix match, bail early
  testBlock =
    ^(es_message_t *esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
      SNTEndpointSecurityRecorder *recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
      __autoreleasing dispatch_semaphore_t *sema, __autoreleasing dispatch_semaphore_t *semaMetrics)

  {
    esMsg->event_type = ES_EVENT_TYPE_NOTIFY_LINK;
    esMsg->event.link.source = &targetFileMatchesRegex;
    prefixTree->InsertPrefix(esMsg->event.link.source->path.data, Unit{});
    Message msg(mockESApi, esMsg);

    OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();

    [recorderClient handleMessage:std::move(msg)
               recordEventMetrics:^(EventDisposition d) {
                 XCTAssertEqual(d, EventDisposition::kDropped);
                 dispatch_semaphore_signal(*semaMetrics);
               }];

    XCTAssertSemaTrue(*semaMetrics, 5, "Metrics not recorded within expected window");
  };

  [self testHandleMessageWithMatchCalls:0 withMissCalls:0 withBlock:testBlock];
}

- (void)testGetTargetFileForPrefixTree {
  // Ensure `GetTargetFileForPrefixTree` returns expected field for each
  // subscribed event type in the `SNTEndpointSecurityRecorder`.
  extern es_file_t *GetTargetFileForPrefixTree(const es_message_t *msg);

  es_file_t closeFile = MakeESFile("close");
  es_file_t linkFile = MakeESFile("link");
  es_file_t renameFile = MakeESFile("rename");
  es_file_t unlinkFile = MakeESFile("unlink");
  es_message_t esMsg;

  esMsg.event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
  esMsg.event.close.target = &closeFile;
  XCTAssertEqual(GetTargetFileForPrefixTree(&esMsg), &closeFile);

  esMsg.event_type = ES_EVENT_TYPE_NOTIFY_LINK;
  esMsg.event.link.source = &linkFile;
  XCTAssertEqual(GetTargetFileForPrefixTree(&esMsg), &linkFile);

  esMsg.event_type = ES_EVENT_TYPE_NOTIFY_RENAME;
  esMsg.event.rename.source = &renameFile;
  XCTAssertEqual(GetTargetFileForPrefixTree(&esMsg), &renameFile);

  esMsg.event_type = ES_EVENT_TYPE_NOTIFY_UNLINK;
  esMsg.event.unlink.target = &unlinkFile;
  XCTAssertEqual(GetTargetFileForPrefixTree(&esMsg), &unlinkFile);

  esMsg.event_type = ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA;
  XCTAssertEqual(GetTargetFileForPrefixTree(&esMsg), nullptr);

  esMsg.event_type = ES_EVENT_TYPE_NOTIFY_EXEC;
  XCTAssertEqual(GetTargetFileForPrefixTree(&esMsg), nullptr);

  esMsg.event_type = ES_EVENT_TYPE_NOTIFY_FORK;
  XCTAssertEqual(GetTargetFileForPrefixTree(&esMsg), nullptr);

  esMsg.event_type = ES_EVENT_TYPE_NOTIFY_EXIT;
  XCTAssertEqual(GetTargetFileForPrefixTree(&esMsg), nullptr);
}

@end
