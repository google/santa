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

#include <map>
#include <memory>
#include <string>

#import "Source/common/SNTCommonEnums.h"
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
  kFileAccessAuthorizer,
};

enum class FileAccessMetricStatus {
  kOK = 0,
  kBlockedUser,
};

using EventCountTuple = std::tuple<Processor, es_event_type_t, EventDisposition>;
using EventTimesTuple = std::tuple<Processor, es_event_type_t>;
using EventStatsTuple = std::tuple<Processor, es_event_type_t>;
using FileAccessMetricsPolicyVersion = std::string;
using FileAccessMetricsPolicyName = std::string;
using FileAccessEventCountTuple =
  std::tuple<FileAccessMetricsPolicyVersion, FileAccessMetricsPolicyName, FileAccessMetricStatus,
             es_event_type_t, FileAccessPolicyDecision>;

class Metrics : public std::enable_shared_from_this<Metrics> {
 public:
  static std::shared_ptr<Metrics> Create(SNTMetricSet *metric_set, uint64_t interval);

  Metrics(dispatch_queue_t q, dispatch_source_t timer_source, uint64_t interval,
          SNTMetricInt64Gauge *event_processing_times, SNTMetricCounter *event_counts,
          SNTMetricCounter *rate_limit_counts, SNTMetricCounter *drop_counts,
          SNTMetricCounter *faa_event_counts, SNTMetricSet *metric_set,
          void (^run_on_first_start)(Metrics *));

  ~Metrics();

  void EstablishConnection();
  void StartPoll();
  void StopPoll();
  void SetInterval(uint64_t interval);

  // Force an immediate flush and export of metrics
  void Export();

  // Used for tracking event sequence numbers to determine if drops occured
  void UpdateEventStats(Processor processor, const es_message_t *msg);

  void SetEventMetrics(Processor processor, es_event_type_t event_type,
                       EventDisposition disposition, int64_t nanos);

  void SetRateLimitingMetrics(Processor processor, int64_t events_rate_limited_count);

  void SetFileAccessEventMetrics(std::string policy_version, std::string rule_name,
                                 FileAccessMetricStatus status, es_event_type_t event_type,
                                 FileAccessPolicyDecision decision);

  friend class santa::santad::MetricsPeer;

 private:
  struct SequenceStats {
    uint64_t next_seq_num = 0;
    int64_t drops = 0;
  };

  void FlushMetrics();
  void ExportLocked(SNTMetricSet *metric_set);

  MOLXPCConnection *metrics_connection_;
  dispatch_queue_t q_;
  dispatch_source_t timer_source_;
  uint64_t interval_;
  SNTMetricInt64Gauge *event_processing_times_;
  SNTMetricCounter *event_counts_;
  SNTMetricCounter *rate_limit_counts_;
  SNTMetricCounter *faa_event_counts_;
  SNTMetricCounter *drop_counts_;
  SNTMetricSet *metric_set_;
  // Tracks whether or not the timer_source should be running.
  // This helps manage dispatch source state to ensure the source is not
  // suspended, resumed, or cancelled while in an improper state.
  bool running_ = false;
  void (^run_on_first_start_)(Metrics *);

  // Separate queue used for setting event metrics
  // Mitigate issues where capturing metrics could be blocked on exporting
  dispatch_queue_t events_q_;

  // Small caches for storing event metrics between metrics export operations
  std::map<EventCountTuple, int64_t> event_counts_cache_;
  std::map<EventTimesTuple, int64_t> event_times_cache_;
  std::map<Processor, int64_t> rate_limit_counts_cache_;
  std::map<FileAccessEventCountTuple, int64_t> faa_event_counts_cache_;
  std::map<EventStatsTuple, SequenceStats> drop_cache_;
};

}  // namespace santa::santad

#endif
