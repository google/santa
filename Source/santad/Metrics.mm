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

#include "Source/santad/Metrics.h"
#include <EndpointSecurity/ESTypes.h>

#include <memory>

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCMetricServiceInterface.h"
#import "Source/santad/SNTApplicationCoreMetrics.h"

static NSString *const kProcessorAuthorizer = @"Authorizer";
static NSString *const kProcessorDeviceManager = @"DeviceManager";
static NSString *const kProcessorRecorder = @"Recorder";
static NSString *const kProcessorTamperResistance = @"TamperResistance";
static NSString *const kProcessorFileAccessAuthorizer = @"FileAccessAuthorizer";

static NSString *const kEventTypeAuthClone = @"AuthClone";
static NSString *const kEventTypeAuthCopyfile = @"AuthCopyfile";
static NSString *const kEventTypeAuthExchangedata = @"AuthExchangedata";
static NSString *const kEventTypeAuthExec = @"AuthExec";
static NSString *const kEventTypeAuthKextload = @"AuthKextload";
static NSString *const kEventTypeAuthLink = @"AuthLink";
static NSString *const kEventTypeAuthMount = @"AuthMount";
static NSString *const kEventTypeAuthOpen = @"AuthOpen";
static NSString *const kEventTypeAuthRemount = @"AuthRemount";
static NSString *const kEventTypeAuthRename = @"AuthRename";
static NSString *const kEventTypeAuthUnlink = @"AuthUnlink";
static NSString *const kEventTypeNotifyClose = @"NotifyClose";
static NSString *const kEventTypeNotifyExchangedata = @"NotifyExchangedata";
static NSString *const kEventTypeNotifyExec = @"NotifyExec";
static NSString *const kEventTypeNotifyExit = @"NotifyExit";
static NSString *const kEventTypeNotifyFork = @"NotifyFork";
static NSString *const kEventTypeNotifyLink = @"NotifyLink";
static NSString *const kEventTypeNotifyRename = @"NotifyRename";
static NSString *const kEventTypeNotifyUnlink = @"NotifyUnlink";
static NSString *const kEventTypeNotifyUnmount = @"NotifyUnmount";

static NSString *const kEventDispositionDropped = @"Dropped";
static NSString *const kEventDispositionProcessed = @"Processed";

namespace santa::santad {

const NSString *ProcessorToString(Processor processor) {
  switch (processor) {
    case Processor::kAuthorizer: return kProcessorAuthorizer;
    case Processor::kDeviceManager: return kProcessorDeviceManager;
    case Processor::kRecorder: return kProcessorRecorder;
    case Processor::kTamperResistance: return kProcessorTamperResistance;
    case Processor::kFileAccessAuthorizer: return kProcessorFileAccessAuthorizer;
    default:
      [NSException raise:@"Invalid processor" format:@"Unknown processor value: %d", processor];
      return nil;
  }
}

const NSString *EventTypeToString(es_event_type_t eventType) {
  switch (eventType) {
    case ES_EVENT_TYPE_AUTH_CLONE: return kEventTypeAuthClone;
    case ES_EVENT_TYPE_AUTH_COPYFILE: return kEventTypeAuthCopyfile;
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA: return kEventTypeAuthExchangedata;
    case ES_EVENT_TYPE_AUTH_EXEC: return kEventTypeAuthExec;
    case ES_EVENT_TYPE_AUTH_KEXTLOAD: return kEventTypeAuthKextload;
    case ES_EVENT_TYPE_AUTH_LINK: return kEventTypeAuthLink;
    case ES_EVENT_TYPE_AUTH_MOUNT: return kEventTypeAuthMount;
    case ES_EVENT_TYPE_AUTH_OPEN: return kEventTypeAuthOpen;
    case ES_EVENT_TYPE_AUTH_REMOUNT: return kEventTypeAuthRemount;
    case ES_EVENT_TYPE_AUTH_RENAME: return kEventTypeAuthRename;
    case ES_EVENT_TYPE_AUTH_UNLINK: return kEventTypeAuthUnlink;
    case ES_EVENT_TYPE_NOTIFY_CLOSE: return kEventTypeNotifyClose;
    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA: return kEventTypeNotifyExchangedata;
    case ES_EVENT_TYPE_NOTIFY_EXEC: return kEventTypeNotifyExec;
    case ES_EVENT_TYPE_NOTIFY_EXIT: return kEventTypeNotifyExit;
    case ES_EVENT_TYPE_NOTIFY_FORK: return kEventTypeNotifyFork;
    case ES_EVENT_TYPE_NOTIFY_LINK: return kEventTypeNotifyLink;
    case ES_EVENT_TYPE_NOTIFY_RENAME: return kEventTypeNotifyRename;
    case ES_EVENT_TYPE_NOTIFY_UNLINK: return kEventTypeNotifyUnlink;
    case ES_EVENT_TYPE_NOTIFY_UNMOUNT: return kEventTypeNotifyUnmount;
    default:
      [NSException raise:@"Invalid event type" format:@"Invalid event type: %d", eventType];
      return nil;
  }
}

const NSString *EventDispositionToString(EventDisposition d) {
  switch (d) {
    case EventDisposition::kDropped: return kEventDispositionDropped;
    case EventDisposition::kProcessed: return kEventDispositionProcessed;
    default:
      [NSException raise:@"Invalid disposition" format:@"Unknown disposition value: %d", d];
      return nil;
  }
}

std::shared_ptr<Metrics> Metrics::Create(SNTMetricSet *metricSet, uint64_t interval) {
  dispatch_queue_t q = dispatch_queue_create("com.google.santa.santametricsservice.q",
                                             DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);

  dispatch_source_t timer_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);

  MOLXPCConnection *metrics_connection = [SNTXPCMetricServiceInterface configuredConnection];

  SNTMetricInt64Gauge *event_processing_times =
    [metricSet int64GaugeWithName:@"/santa/event_processing_time"
                       fieldNames:@[ @"Processor", @"Event" ]
                         helpText:@"Time to process various event types by each processor"];

  SNTMetricCounter *event_counts =
    [metricSet counterWithName:@"/santa/event_count"
                    fieldNames:@[ @"Processor", @"Event", @"Disposition" ]
                      helpText:@"Events received and processed by each processor"];

  std::shared_ptr<Metrics> metrics = std::make_shared<Metrics>(
    metrics_connection, q, timer_source, interval, event_processing_times, event_counts, ^() {
      SNTRegisterCoreMetrics();
      [metrics_connection resume];
    });

  std::weak_ptr<Metrics> weak_metrics(metrics);
  dispatch_source_set_event_handler(metrics->timer_source_, ^{
    std::shared_ptr<Metrics> shared_metrics = weak_metrics.lock();
    if (!shared_metrics) {
      return;
    }

    [[shared_metrics->metrics_connection_ remoteObjectProxy]
      exportForMonitoring:[metricSet export]];
  });

  return metrics;
}

Metrics::Metrics(MOLXPCConnection *metrics_connection, dispatch_queue_t q,
                 dispatch_source_t timer_source, uint64_t interval,
                 SNTMetricInt64Gauge *event_processing_times, SNTMetricCounter *event_counts,
                 void (^run_on_first_start)(void))
    : q_(q),
      timer_source_(timer_source),
      interval_(interval),
      event_processing_times_(event_processing_times),
      event_counts_(event_counts),
      running_(false),
      run_on_first_start_(run_on_first_start) {
  metrics_connection_ = metrics_connection;
  SetInterval(interval_);

  events_q_ = dispatch_queue_create("com.google.santa.santametricsservice.events_q",
                                    DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
}

Metrics::~Metrics() {
  if (!running_) {
    // The timer_source_ must be resumed to ensure it has a proper retain count before being
    // destroyed. Additionally, it should first be cancelled to ensure the timer isn't ever fired
    // (see man page for `dispatch_source_cancel(3)`).
    dispatch_source_cancel(timer_source_);
    dispatch_resume(timer_source_);
  }
}

void Metrics::SetInterval(uint64_t interval) {
  dispatch_sync(q_, ^{
    LOGI(@"Setting metrics interval to %llu (exporting? %s)", interval, running_ ? "YES" : "NO");
    interval_ = interval;
    dispatch_source_set_timer(timer_source_, dispatch_time(DISPATCH_TIME_NOW, 0),
                              interval_ * NSEC_PER_SEC, 250 * NSEC_PER_MSEC);
  });
}

void Metrics::StartPoll() {
  static dispatch_once_t once_token;
  dispatch_once(&once_token, ^{
    run_on_first_start_();
  });

  dispatch_sync(q_, ^{
    if (!running_) {
      LOGI(@"Starting to export metrics every %llu seconds", interval_);
      running_ = true;
      dispatch_resume(timer_source_);
    } else {
      LOGW(@"Attempted to start metrics poll while already started");
    }
  });
}

void Metrics::StopPoll() {
  dispatch_sync(q_, ^{
    if (running_) {
      LOGI(@"Stopping metrics export");
      dispatch_suspend(timer_source_);
      running_ = false;
    } else {
      LOGW(@"Attempted to stop metrics poll while already stopped");
    }
  });
}

void Metrics::SetEventMetrics(Processor processor, es_event_type_t event_type,
                              EventDisposition event_disposition, int64_t nanos) {
  dispatch_async(events_q_, ^{
    NSString *processorName = (NSString *)ProcessorToString(processor);
    NSString *eventName = (NSString *)EventTypeToString(event_type);
    NSString *disposition = (NSString *)EventDispositionToString(event_disposition);

    [event_counts_ incrementForFieldValues:@[ processorName, eventName, disposition ]];
    [event_processing_times_ set:nanos forFieldValues:@[ processorName, eventName ]];
  });
}

}  // namespace santa::santad
