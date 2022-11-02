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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_SPOOL_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_SPOOL_H

#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "Source/santad/Logs/EndpointSecurity/Serializers/Protobuf.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool_log_batch_writer.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Writer.h"

// Forward declarations
namespace santa::santad::logs::endpoint_security::writers {
class SpoolPeer;
}

namespace santa::santad::logs::endpoint_security::writers {
class Spool : public Writer, public std::enable_shared_from_this<Spool> {
 public:
  // Factory
  static std::shared_ptr<Spool> Create(
    std::shared_ptr<santa::santad::logs::endpoint_security::serializers::Protobuf> data_source,
    std::string_view base_dir, size_t max_spool_disk_size, size_t spool_file_size_threshold,
    size_t max_spool_batch_size, uint64_t flush_timeout_ms);

  Spool(std::shared_ptr<santa::santad::logs::endpoint_security::serializers::Protobuf> data_source,
        dispatch_queue_t q, dispatch_source_t timer_source, std::string_view base_dir,
        size_t max_spool_disk_size, size_t spool_file_size_threshold, size_t max_spool_batch_size,
        void (^write_complete_f)(void) = nullptr, void (^flush_task_complete_f)(void) = nullptr);

  ~Spool();

  void Write(std::vector<uint8_t> &&bytes) override;
  bool Flush();

  void BeginPeriodicTask();
  void WriteFromDataSource(size_t threshold);

  // Peer class for testing
  friend class santa::santad::logs::endpoint_security::writers::SpoolPeer;

 private:
  std::shared_ptr<santa::santad::logs::endpoint_security::serializers::Protobuf> data_source_;
  dispatch_queue_t q_ = NULL;
  dispatch_source_t timer_source_ = NULL;
  ::fsspool::FsSpoolWriter spool_writer_;
  ::fsspool::FsSpoolLogBatchWriter log_batch_writer_;
  std::string type_url_;
  const size_t spool_file_size_threshold_;
  const size_t max_spool_batch_size_;
  bool flush_task_started_ = false;
  void (^write_complete_f_)(void);
  void (^flush_task_complete_f_)(void);
};

}  // namespace santa::santad::logs::endpoint_security::writers

#endif
