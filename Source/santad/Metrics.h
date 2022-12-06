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

#ifndef SANTA__SANTAD__METRICS_H
#define SANTA__SANTAD__METRICS_H

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <MOLXPCConnection/MOLXPCConnection.h>
#include <dispatch/dispatch.h>

#include <memory>

#import "Source/common/SNTMetricSet.h"

namespace santa::santad {

// Test interface - forward declaration
class MetricsPeer;

enum class EventDisposition {
  kProcessed = 0,
  kDropped,
};

enum class Processor {
  kUnknown = 0,
  kAuthorizer,
  kDeviceManager,
  kRecorder,
  kTamperResistance,
};

class Metrics : public std::enable_shared_from_this<Metrics> {
 public:
  static std::shared_ptr<Metrics> Create(SNTMetricSet *metricSet, uint64_t interval);

  Metrics(MOLXPCConnection *metrics_connection, dispatch_queue_t q, dispatch_source_t timer_source,
          uint64_t interval, SNTMetricInt64Gauge *event_processing_times,
          SNTMetricCounter *event_counts, void (^run_on_first_start)(void));

  ~Metrics();

  void StartPoll();
  void StopPoll();
  void SetInterval(uint64_t interval);

  void SetEventMetrics(Processor processor, es_event_type_t event_type,
                       EventDisposition disposition, int64_t nanos);

  friend class santa::santad::MetricsPeer;

 private:
  MOLXPCConnection *metrics_connection_;
  dispatch_queue_t q_;
  dispatch_source_t timer_source_;
  uint64_t interval_;
  SNTMetricInt64Gauge *event_processing_times_;
  SNTMetricCounter *event_counts_;
  // Tracks whether or not the timer_source should be running.
  // This helps manage dispatch source state to ensure the source is not
  // suspended, resumed, or cancelled while in an improper state.
  bool running_;
  void (^run_on_first_start_)(void);

  // Separate queue used for setting event metrics
  // Mitigate issues where capturing metrics could be blocked on exporting
  dispatch_queue_t events_q_;
};

}  // namespace santa::santad

#endif
