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

#import "Source/santad/Logs/EndpointSecurity/Writers/Spool.h"

#import "Source/common/SNTLogging.h"
#include "Source/common/santa_proto_include_wrapper.h"
#include "absl/strings/string_view.h"

using santa::santad::logs::endpoint_security::serializers::Protobuf;

static const char *kTypeGoogleApisComPrefix = "type.googleapis.com/";

namespace santa::santad::logs::endpoint_security::writers {

std::shared_ptr<Spool> Spool::Create(std::shared_ptr<Protobuf> data_source,
                                     std::string_view base_dir, size_t max_spool_disk_size,
                                     size_t spool_file_size_threshold, size_t max_spool_batch_size,
                                     uint64_t flush_timeout_ms) {
  dispatch_queue_t q = dispatch_queue_create("com.google.santa.daemon.file_base_q",
                                             DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
  dispatch_source_t timer_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
  dispatch_source_set_timer(timer_source, dispatch_time(DISPATCH_TIME_NOW, 0),
                            NSEC_PER_MSEC * flush_timeout_ms, 0);

  auto spool_writer =
    std::make_shared<Spool>(std::move(data_source), q, timer_source, base_dir, max_spool_disk_size,
                            spool_file_size_threshold, max_spool_batch_size);

  spool_writer->BeginPeriodicTask();

  return spool_writer;
}

Spool::Spool(std::shared_ptr<Protobuf> data_source, dispatch_queue_t q,
             dispatch_source_t timer_source, std::string_view base_dir, size_t max_spool_disk_size,
             size_t spool_file_size_threshold, size_t max_spool_batch_size,
             void (^write_complete_f)(void), void (^flush_task_complete_f)(void))
    : data_source_(std::move(data_source)),
      q_(q),
      timer_source_(timer_source),
      spool_writer_(absl::string_view(base_dir.data(), base_dir.length()), max_spool_disk_size),
      log_batch_writer_(&spool_writer_, max_spool_batch_size),
      spool_file_size_threshold_(spool_file_size_threshold),
      max_spool_batch_size_(max_spool_batch_size),
      write_complete_f_(write_complete_f),
      flush_task_complete_f_(flush_task_complete_f) {
  type_url_ =
    kTypeGoogleApisComPrefix + ::santa::pb::v1::SantaMessageBatch::descriptor()->full_name();
}

Spool::~Spool() {
  // Note: `log_batch_writer_` is automatically flushed when destroyed
  if (!flush_task_started_) {
    // The timer_source_ must be resumed to ensure it has a proper retain count before being
    // destroyed. Additionally, it should first be cancelled to ensure the timer isn't ever fired
    // (see man page for `dispatch_source_cancel(3)`).
    dispatch_source_cancel(timer_source_);
    dispatch_resume(timer_source_);
  }
}

// Note: Not thread safe. Calls should be gated by `q_`.
void Spool::WriteFromDataSource(size_t threshold) {
  std::string serialized_output;

  bool result = data_source_->Drain(&serialized_output, threshold);

  if (result) {
    google::protobuf::Any any;
    any.set_type_url(type_url_);
#if SANTA_OPEN_SOURCE
    any.set_value(serialized_output);
#else
    any.set_value(absl::string_view(serialized_output));
#endif

    auto status = log_batch_writer_.WriteMessage(any);
    if (!status.ok()) {
      LOGE(@"Logging from data source failed with: %s", status.ToString().c_str());
    }
  }
}

void Spool::BeginPeriodicTask() {
  if (flush_task_started_) {
    return;
  }

  std::weak_ptr<Spool> weak_writer = weak_from_this();
  dispatch_source_set_event_handler(timer_source_, ^{
    std::shared_ptr<Spool> shared_writer = weak_writer.lock();
    if (!shared_writer) {
      return;
    }

    shared_writer->WriteFromDataSource(0);

    if (!shared_writer->Flush()) {
      LOGE(@"Spool writer: periodic flush failed.");
    }

    if (shared_writer->flush_task_complete_f_) {
      shared_writer->flush_task_complete_f_();
    }
  });

  dispatch_resume(timer_source_);
  flush_task_started_ = true;
}

bool Spool::Flush() {
  return log_batch_writer_.Flush().ok();
}

void Spool::Write([[maybe_unused]] std::vector<uint8_t> &&bytes) {
  auto shared_this = shared_from_this();

  dispatch_async(q_, ^{
    shared_this->WriteFromDataSource(spool_file_size_threshold_);

    if (shared_this->write_complete_f_) {
      shared_this->write_complete_f_();
    }
  });
}

}  // namespace santa::santad::logs::endpoint_security::writers
