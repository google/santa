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

#import "Source/santad/Logs/EndpointSecurity/Writers/File.h"

#include <memory>

namespace santa::santad::logs::endpoint_security::writers {

// Flush the write buffer every 5 seconds
static const uint64_t kFlushBufferTimeoutMS = 5000;
// Batch writes up to 128kb
static const uint64_t kBufferBatchSizeBytes = (1024 * 128);
// Reserve an extra 4kb of buffer space to account for event overflow
static const uint64_t kMaxExpectedWriteSizeBytes = 4096;

std::shared_ptr<File> File::Create(NSString* path) {
  dispatch_queue_t q = dispatch_queue_create("com.google.santa.file_event_log",
                                             DISPATCH_QUEUE_SERIAL);
  dispatch_source_t timer_source = dispatch_source_create(
      DISPATCH_SOURCE_TYPE_TIMER,
      0,
      0,
      q);

  dispatch_source_set_timer(timer_source,
                            dispatch_time(DISPATCH_TIME_NOW, 0),
                            NSEC_PER_MSEC * kFlushBufferTimeoutMS,
                            0);

  auto ret_writer = std::make_shared<File>(path, q, timer_source);
  ret_writer->WatchLogFile();

  auto shared_this = ret_writer->shared_from_this();
  dispatch_source_set_event_handler(timer_source, ^{
    shared_this->FlushBuffer();
  });

  dispatch_resume(timer_source);


  return ret_writer;
}

File::File(NSString* path, dispatch_queue_t q, dispatch_source_t timer_source)
    : q_(q), timer_source_(timer_source), watch_source_(nullptr) {
  path_ = path;
  buffer_.reserve(kBufferBatchSizeBytes + kMaxExpectedWriteSizeBytes);
  OpenFileHandle();
}

void File::WatchLogFile() {
  auto weak_this = weak_from_this();

  if (watch_source_) {
    dispatch_source_cancel(watch_source_);
  }

  watch_source_ = dispatch_source_create(
      DISPATCH_SOURCE_TYPE_VNODE,
      file_handle_.fileDescriptor,
      DISPATCH_VNODE_DELETE | DISPATCH_VNODE_RENAME,
      q_);

  dispatch_source_set_event_handler(watch_source_, ^{
    std::shared_ptr<File> shared_this = weak_this.lock();
    if (!shared_this) {
      return;
    }

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

void File::Write(const std::vector<uint8_t>& bytes) {
  dispatch_async(q_, ^{
    buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
    if (buffer_.size() > kBufferBatchSizeBytes) {
      FlushBuffer();
    }
  });
}

// IMPORTANT: Not thread safe.
void File::FlushBuffer() {
  write(file_handle_.fileDescriptor, buffer_.data(), buffer_.size());
  buffer_.clear();
}

} // namespace santa::santad::logs::endpoint_security::writers
