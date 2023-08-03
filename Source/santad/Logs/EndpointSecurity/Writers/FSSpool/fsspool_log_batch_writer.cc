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

#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool_log_batch_writer.h"

#include <os/log.h>

#include <string>

#include "absl/status/status.h"

namespace fsspool {

FsSpoolLogBatchWriter::FsSpoolLogBatchWriter(FsSpoolWriter* fs_spool_writer,
                                             size_t max_batch_size)
    : writer_(fs_spool_writer), max_batch_size_(max_batch_size) {
  cache_.mutable_records()->Reserve(max_batch_size_);
}

FsSpoolLogBatchWriter::~FsSpoolLogBatchWriter() {
  absl::Status s = FlushNoLock();
  if (!s.ok()) {
    os_log(OS_LOG_DEFAULT, "Flush() failed with %s",
           s.ToString(absl::StatusToStringMode::kWithEverything).c_str());
  }
}

absl::Status FsSpoolLogBatchWriter::Flush() {
  absl::MutexLock lock(&cache_mutex_);
  return FlushNoLock();
}

absl::Status FsSpoolLogBatchWriter::FlushNoLock() {
  if (cache_.mutable_records()->empty()) {
    return absl::OkStatus();
  }
  std::string msg;
  if (!cache_.SerializeToString(&msg)) {
    return absl::InternalError("Failed to serialize internal LogBatch cache.");
  }
  {
    absl::MutexLock lock(&writer_mutex_);
    if (absl::Status status = writer_->WriteMessage(msg); !status.ok()) {
      return status;
    }
  }
  // We assign a new LogBatch() object here instead of calling Clear() method to
  // make sure the memory used by the cache_ is actually freed. It seems that
  // internal implementation of protobuf has some very generous way of managing
  // memory allocations and in certain scenarios it keeps objects for a very
  // long time (forever?).
  cache_ = santa::fsspool::binaryproto::LogBatch();
  cache_.mutable_records()->Reserve(max_batch_size_);
  return absl::OkStatus();
}

absl::Status FsSpoolLogBatchWriter::WriteMessage(
    const ::google::protobuf::Any& msg) {
  absl::MutexLock lock(&cache_mutex_);
  if (cache_.records_size() >= max_batch_size_) {
    if (absl::Status status = FlushNoLock(); !status.ok()) {
      return status;
    }
  }
  *cache_.mutable_records()->Add() = msg;
  return absl::OkStatus();
}

}  // namespace fsspool
