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

#include "Source/santad/Logs/EndpointSecurity/Writers/File.h"

#include <memory>

#include "Source/common/BranchPrediction.h"

namespace santa::santad::logs::endpoint_security::writers {

std::shared_ptr<File> File::Create(NSString *path, uint64_t flush_timeout_ms,
                                   size_t batch_size_bytes, size_t max_expected_write_size_bytes) {
  dispatch_queue_t q = dispatch_queue_create("com.google.santa.daemon.file_event_log",
                                             DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
  dispatch_source_t timer_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);

  dispatch_source_set_timer(timer_source, dispatch_time(DISPATCH_TIME_NOW, 0),
                            NSEC_PER_MSEC * flush_timeout_ms, 0);

  auto ret_writer =
    std::make_shared<File>(path, batch_size_bytes, max_expected_write_size_bytes, q, timer_source);
  ret_writer->WatchLogFile();

  std::weak_ptr<File> weak_writer(ret_writer);
  dispatch_source_set_event_handler(ret_writer->timer_source_, ^{
    std::shared_ptr<File> shared_writer = weak_writer.lock();
    if (!shared_writer) {
      return;
    }
    shared_writer->FlushBuffer();
  });

  dispatch_resume(ret_writer->timer_source_);

  return ret_writer;
}

File::File(NSString *path, size_t batch_size_bytes, size_t max_expected_write_size_bytes,
           dispatch_queue_t q, dispatch_source_t timer_source)
    : buffer_(batch_size_bytes + max_expected_write_size_bytes),
      batch_size_bytes_(batch_size_bytes),
      q_(q),
      timer_source_(timer_source),
      watch_source_(nullptr) {
  path_ = path;
  OpenFileHandle();
}

void File::WatchLogFile() {
  if (watch_source_) {
    dispatch_source_cancel(watch_source_);
  }

  watch_source_ = dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, file_handle_.fileDescriptor,
                                         DISPATCH_VNODE_DELETE | DISPATCH_VNODE_RENAME, q_);

  auto shared_this = shared_from_this();
  dispatch_source_set_event_handler(watch_source_, ^{
    [shared_this->file_handle_ closeFile];
    shared_this->OpenFileHandle();
    shared_this->WatchLogFile();
  });

  dispatch_resume(watch_source_);
}

File::~File() {
  if (timer_source_) {
    dispatch_source_cancel(timer_source_);
  }
}

// IMPORTANT: Not thread safe.
void File::OpenFileHandle() {
  NSFileManager *fm = [NSFileManager defaultManager];
  if (![fm fileExistsAtPath:path_]) {
    [fm createFileAtPath:path_ contents:nil attributes:nil];
  }
  file_handle_ = [NSFileHandle fileHandleForWritingAtPath:path_];
  [file_handle_ seekToEndOfFile];
}

void File::Write(std::vector<uint8_t> &&bytes) {
  auto shared_this = shared_from_this();

  // Workaround to move `bytes` into the block without a copy
  __block std::vector<uint8_t> temp_bytes = std::move(bytes);

  dispatch_async(q_, ^{
    std::vector<uint8_t> moved_bytes = std::move(temp_bytes);

    CopyData(moved_bytes);

    if (ShouldFlush()) {
      shared_this->FlushBuffer();
    }
  });
}

bool File::ShouldFlush() {
  return buffer_offset_ >= batch_size_bytes_;
}

// IMPORTANT: Not thread safe.
void File::EnsureCapacity(size_t additional_bytes) {
  if ((buffer_offset_ + additional_bytes) > buffer_.capacity()) {
    buffer_.resize(buffer_.capacity() * 2);
  }
}

// IMPORTANT: Not thread safe.
void File::CopyData(const std::vector<uint8_t> &bytes) {
  EnsureCapacity(bytes.size());
  std::copy(bytes.begin(), bytes.end(), buffer_.begin() + buffer_offset_);
  buffer_offset_ += bytes.size();
}

// IMPORTANT: Not thread safe.
void File::FlushBuffer() {
  if (likely(buffer_offset_ > 0)) {
    write(file_handle_.fileDescriptor, buffer_.data(), buffer_offset_);

    // After flushing, reset the offset back to 0
    buffer_offset_ = 0;
  }
}

}  // namespace santa::santad::logs::endpoint_security::writers
