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
#include <dispatch/dispatch.h>

#include <map>

#include "Source/common/SNTMetricSet.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/Metrics.h"

using santa::santad::EventCountTuple;
using santa::santad::EventDisposition;
using santa::santad::EventTimesTuple;
using santa::santad::FileAccessEventCountTuple;
using santa::santad::Processor;

namespace santa::santad {

extern NSString *const ProcessorToString(Processor processor);
extern NSString *const EventTypeToString(es_event_type_t eventType);
extern NSString *const EventDispositionToString(EventDisposition d);
extern NSString *const FileAccessMetricStatusToString(FileAccessMetricStatus status);
extern NSString *const FileAccessPolicyDecisionToString(FileAccessPolicyDecision decision);

class MetricsPeer : public Metrics {
 public:
  // Make base class constructors visible
  using Metrics::FlushMetrics;
  using Metrics::Metrics;

  bool IsRunning() { return running_; }

  uint64_t Interval() { return interval_; }

  std::map<EventCountTuple, int64_t> &EventCounts() { return event_counts_cache_; };
  std::map<EventTimesTuple, int64_t> &EventTimes() { return event_times_cache_; };
  std::map<Processor, int64_t> &RateLimitCounts() { return rate_limit_counts_cache_; };

  using Metrics::faa_event_counts_cache_;
};

}  // namespace santa::santad

using santa::santad::EventDispositionToString;
using santa::santad::EventTypeToString;
using santa::santad::FileAccessMetricStatus;
using santa::santad::FileAccessMetricStatusToString;
using santa::santad::FileAccessPolicyDecisionToString;
using santa::santad::MetricsPeer;
using santa::santad::ProcessorToString;

@interface MetricsTest : XCTestCase
@property dispatch_queue_t q;
@property dispatch_semaphore_t sema;
@end

@implementation MetricsTest

- (void)setUp {
  self.q = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
  XCTAssertNotNil(self.q);
  self.sema = dispatch_semaphore_create(0);
}

- (void)testStartStop {
  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  auto metrics = std::make_shared<MetricsPeer>(self.q, timer, 100, nil, nil, nil, nil, nil,
                                               ^(santa::santad::Metrics *m) {
                                                 dispatch_semaphore_signal(self.sema);
                                               });

  XCTAssertFalse(metrics->IsRunning());

  metrics->StartPoll();
  XCTAssertEqual(0, dispatch_semaphore_wait(self.sema, DISPATCH_TIME_NOW),
                 "Initialization block never called");

  // Should be marked running after starting
  XCTAssertTrue(metrics->IsRunning());

  metrics->StartPoll();

  // Ensure the initialization block isn't called a second time
  XCTAssertNotEqual(0, dispatch_semaphore_wait(self.sema, DISPATCH_TIME_NOW),
                    "Initialization block called second time unexpectedly");

  // Double-start doesn't change the running state
  XCTAssertTrue(metrics->IsRunning());

  metrics->StopPoll();

  // After stopping, the internal state is no longer marked running
  XCTAssertFalse(metrics->IsRunning());

  metrics->StopPoll();

  // Double-stop doesn't change the running state
  XCTAssertFalse(metrics->IsRunning());
}

- (void)testSetInterval {
  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  auto metrics = std::make_shared<MetricsPeer>(self.q, timer, 100, nil, nil, nil, nil, nil,
                                               ^(santa::santad::Metrics *m){
                                               });

  XCTAssertEqual(100, metrics->Interval());

  metrics->SetInterval(200);
  XCTAssertEqual(200, metrics->Interval());
}

- (void)testProcessorToString {
  std::map<Processor, NSString *> processorToString = {
    {Processor::kAuthorizer, @"Authorizer"},
    {Processor::kDeviceManager, @"DeviceManager"},
    {Processor::kRecorder, @"Recorder"},
    {Processor::kTamperResistance, @"TamperResistance"},
  };

  for (const auto &kv : processorToString) {
    XCTAssertEqualObjects(ProcessorToString(kv.first), kv.second);
  }

  XCTAssertThrows(ProcessorToString((Processor)12345));
}

- (void)testEventTypeToString {
  std::map<es_event_type_t, NSString *> eventTypeToString = {
    {ES_EVENT_TYPE_AUTH_CLONE, @"AuthClone"},
    {ES_EVENT_TYPE_AUTH_COPYFILE, @"AuthCopyfile"},
    {ES_EVENT_TYPE_AUTH_CREATE, @"AuthCreate"},
    {ES_EVENT_TYPE_AUTH_EXCHANGEDATA, @"AuthExchangedata"},
    {ES_EVENT_TYPE_AUTH_EXEC, @"AuthExec"},
    {ES_EVENT_TYPE_AUTH_KEXTLOAD, @"AuthKextload"},
    {ES_EVENT_TYPE_AUTH_LINK, @"AuthLink"},
    {ES_EVENT_TYPE_AUTH_MOUNT, @"AuthMount"},
    {ES_EVENT_TYPE_AUTH_REMOUNT, @"AuthRemount"},
    {ES_EVENT_TYPE_AUTH_RENAME, @"AuthRename"},
    {ES_EVENT_TYPE_AUTH_TRUNCATE, @"AuthTruncate"},
    {ES_EVENT_TYPE_AUTH_UNLINK, @"AuthUnlink"},
    {ES_EVENT_TYPE_NOTIFY_CLOSE, @"NotifyClose"},
    {ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, @"NotifyExchangedata"},
    {ES_EVENT_TYPE_NOTIFY_EXEC, @"NotifyExec"},
    {ES_EVENT_TYPE_NOTIFY_EXIT, @"NotifyExit"},
    {ES_EVENT_TYPE_NOTIFY_FORK, @"NotifyFork"},
    {ES_EVENT_TYPE_NOTIFY_LINK, @"NotifyLink"},
    {ES_EVENT_TYPE_NOTIFY_RENAME, @"NotifyRename"},
    {ES_EVENT_TYPE_NOTIFY_UNLINK, @"NotifyUnlink"},
    {ES_EVENT_TYPE_NOTIFY_UNMOUNT, @"NotifyUnmount"},
  };

  for (const auto &kv : eventTypeToString) {
    XCTAssertEqualObjects(EventTypeToString(kv.first), kv.second);
  }

  XCTAssertThrows(EventTypeToString((es_event_type_t)12345));
}

- (void)testEventDispositionToString {
  std::map<EventDisposition, NSString *> dispositionToString = {
    {EventDisposition::kDropped, @"Dropped"},
    {EventDisposition::kProcessed, @"Processed"},
  };

  for (const auto &kv : dispositionToString) {
    XCTAssertEqualObjects(EventDispositionToString(kv.first), kv.second);
  }

  XCTAssertThrows(EventDispositionToString((EventDisposition)12345));
}

- (void)testFileAccessMetricStatusToString {
  std::map<FileAccessMetricStatus, NSString *> statusToString = {
    {FileAccessMetricStatus::kOK, @"OK"},
    {FileAccessMetricStatus::kBlockedUser, @"BLOCKED_USER"},
  };

  for (const auto &kv : statusToString) {
    XCTAssertEqualObjects(FileAccessMetricStatusToString(kv.first), kv.second);
  }

  XCTAssertThrows(FileAccessMetricStatusToString((FileAccessMetricStatus)12345));
}

- (void)testFileAccessPolicyDecisionToString {
  std::map<FileAccessPolicyDecision, NSString *> decisionToString = {
    {FileAccessPolicyDecision::kDenied, @"Denied"},
    {FileAccessPolicyDecision::kDeniedInvalidSignature, @"Denied"},
    {FileAccessPolicyDecision::kDeniedInvalidSignature, @"Denied"},
  };

  for (const auto &kv : decisionToString) {
    XCTAssertEqualObjects(FileAccessPolicyDecisionToString(kv.first), kv.second);
  }

  std::set<FileAccessPolicyDecision> decisionToStringThrows = {
    FileAccessPolicyDecision::kNoPolicy,
    FileAccessPolicyDecision::kAllowed,
    FileAccessPolicyDecision::kAllowedReadAccess,
    (FileAccessPolicyDecision)12345,
  };
  for (const auto &v : decisionToStringThrows) {
    XCTAssertThrows(FileAccessPolicyDecisionToString(v));
  }
}

- (void)testSetEventMetrics {
  int64_t nanos = 1234;

  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  auto metrics = std::make_shared<MetricsPeer>(self.q, timer, 100, nil, nil, nil, nil, nil,
                                               ^(santa::santad::Metrics *m){
                                                 // This block intentionally left blank
                                               });

  // Initial maps are empty
  XCTAssertEqual(metrics->EventCounts().size(), 0);
  XCTAssertEqual(metrics->EventTimes().size(), 0);

  metrics->SetEventMetrics(Processor::kAuthorizer, ES_EVENT_TYPE_AUTH_EXEC,
                           EventDisposition::kProcessed, nanos);

  // Check sizes after setting metrics once
  XCTAssertEqual(metrics->EventCounts().size(), 1);
  XCTAssertEqual(metrics->EventTimes().size(), 1);

  metrics->SetEventMetrics(Processor::kAuthorizer, ES_EVENT_TYPE_AUTH_EXEC,
                           EventDisposition::kProcessed, nanos);
  metrics->SetEventMetrics(Processor::kAuthorizer, ES_EVENT_TYPE_AUTH_OPEN,
                           EventDisposition::kProcessed, nanos * 2);

  // Re-check expected counts. One was an update, so should only be 2 items
  XCTAssertEqual(metrics->EventCounts().size(), 2);
  XCTAssertEqual(metrics->EventTimes().size(), 2);

  // Check map values
  EventCountTuple ecExec{Processor::kAuthorizer, ES_EVENT_TYPE_AUTH_EXEC,
                         EventDisposition::kProcessed};
  EventCountTuple ecOpen{Processor::kAuthorizer, ES_EVENT_TYPE_AUTH_OPEN,
                         EventDisposition::kProcessed};
  EventTimesTuple etExec{Processor::kAuthorizer, ES_EVENT_TYPE_AUTH_EXEC};
  EventTimesTuple etOpen{Processor::kAuthorizer, ES_EVENT_TYPE_AUTH_OPEN};

  XCTAssertEqual(metrics->EventCounts()[ecExec], 2);
  XCTAssertEqual(metrics->EventCounts()[ecOpen], 1);
  XCTAssertEqual(metrics->EventTimes()[etExec], nanos);
  XCTAssertEqual(metrics->EventTimes()[etOpen], nanos * 2);
}

- (void)testSetRateLimitingMetrics {
  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  auto metrics = std::make_shared<MetricsPeer>(self.q, timer, 100, nil, nil, nil, nil, nil,
                                               ^(santa::santad::Metrics *m){
                                                 // This block intentionally left blank
                                               });

  // Initial map is empty
  XCTAssertEqual(metrics->RateLimitCounts().size(), 0);

  metrics->SetRateLimitingMetrics(Processor::kFileAccessAuthorizer, 123);

  // Check sizes after setting metrics once
  XCTAssertEqual(metrics->RateLimitCounts().size(), 1);

  metrics->SetRateLimitingMetrics(Processor::kFileAccessAuthorizer, 456);
  metrics->SetRateLimitingMetrics(Processor::kAuthorizer, 789);

  // Re-check expected counts. One was an update, so should only be 2 items
  XCTAssertEqual(metrics->RateLimitCounts().size(), 2);

  // Check map values
  XCTAssertEqual(metrics->RateLimitCounts()[Processor::kFileAccessAuthorizer], 123 + 456);
  XCTAssertEqual(metrics->RateLimitCounts()[Processor::kAuthorizer], 789);
}

- (void)testSetFileAccessEventMetrics {
  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  auto metrics = std::make_shared<MetricsPeer>(self.q, timer, 100, nil, nil, nil, nil, nil,
                                               ^(santa::santad::Metrics *m){
                                                 // This block intentionally left blank
                                               });

  // Initial map is empty
  XCTAssertEqual(metrics->faa_event_counts_cache_.size(), 0);

  metrics->SetFileAccessEventMetrics("v1.0", "rule_abc", FileAccessMetricStatus::kOK,
                                     ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied);

  // Check sizes after setting metrics once
  XCTAssertEqual(metrics->faa_event_counts_cache_.size(), 1);

  // Update the previous metric
  metrics->SetFileAccessEventMetrics("v1.0", "rule_abc", FileAccessMetricStatus::kOK,
                                     ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied);

  // Add a second metric
  metrics->SetFileAccessEventMetrics("v1.0", "rule_xyz", FileAccessMetricStatus::kOK,
                                     ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied);

  // Re-check expected counts. One was an update, so should only be 2 items
  XCTAssertEqual(metrics->faa_event_counts_cache_.size(), 2);

  FileAccessEventCountTuple ruleAbc{"v1.0", "rule_abc", FileAccessMetricStatus::kOK,
                                    ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied};
  FileAccessEventCountTuple ruleXyz{"v1.0", "rule_xyz", FileAccessMetricStatus::kOK,
                                    ES_EVENT_TYPE_AUTH_OPEN, FileAccessPolicyDecision::kDenied};

  XCTAssertEqual(metrics->faa_event_counts_cache_[ruleAbc], 2);
  XCTAssertEqual(metrics->faa_event_counts_cache_[ruleXyz], 1);
}

- (void)testFlushMetrics {
  id mockEventProcessingTimes = OCMClassMock([SNTMetricInt64Gauge class]);
  id mockEventCounts = OCMClassMock([SNTMetricCounter class]);
  int64_t nanos = 1234;

  OCMStub([mockEventCounts incrementBy:0 forFieldValues:[OCMArg any]])
    .ignoringNonObjectArgs()
    .andDo(^(NSInvocation *inv) {
      dispatch_semaphore_signal(self.sema);
    });

  OCMStub([(SNTMetricInt64Gauge *)mockEventProcessingTimes set:nanos forFieldValues:[OCMArg any]])
    .ignoringNonObjectArgs()
    .andDo(^(NSInvocation *inv) {
      dispatch_semaphore_signal(self.sema);
    });

  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  auto metrics = std::make_shared<MetricsPeer>(self.q, timer, 100, mockEventProcessingTimes,
                                               mockEventCounts, mockEventCounts, nil, nil,
                                               ^(santa::santad::Metrics *m){
                                                 // This block intentionally left blank
                                               });

  metrics->SetEventMetrics(Processor::kAuthorizer, ES_EVENT_TYPE_AUTH_EXEC,
                           EventDisposition::kProcessed, nanos);
  metrics->SetEventMetrics(Processor::kAuthorizer, ES_EVENT_TYPE_AUTH_OPEN,
                           EventDisposition::kProcessed, nanos * 2);
  metrics->SetRateLimitingMetrics(Processor::kFileAccessAuthorizer, 123);

  // First ensure we have the expected map sizes
  XCTAssertEqual(metrics->EventCounts().size(), 2);
  XCTAssertEqual(metrics->EventTimes().size(), 2);
  XCTAssertEqual(metrics->RateLimitCounts().size(), 1);

  metrics->FlushMetrics();

  // After setting two different event metrics, we expect the sema to be hit
  // five times - twice each for the event counts and event times maps, and
  // once for the rate limit count map.
  XCTAssertSemaTrue(self.sema, 5, "Failed waiting for metrics to flush (1)");
  XCTAssertSemaTrue(self.sema, 5, "Failed waiting for metrics to flush (2)");
  XCTAssertSemaTrue(self.sema, 5, "Failed waiting for metrics to flush (3)");
  XCTAssertSemaTrue(self.sema, 5, "Failed waiting for metrics to flush (4)");
  XCTAssertSemaTrue(self.sema, 5, "Failed waiting for metrics to flush (5)");

  // After a flush, map sizes should be reset to 0
  XCTAssertEqual(metrics->EventCounts().size(), 0);
  XCTAssertEqual(metrics->EventTimes().size(), 0);
  XCTAssertEqual(metrics->RateLimitCounts().size(), 0);
}

@end
