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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FILE_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FILE_H

#include "Source/santad/Logs/EndpointSecurity/Writers/Writer.h"

#include <dispatch/dispatch.h>
#include <Foundation/Foundation.h>

#include <memory>
#include <vector>

// Forward declarations
namespace santa::santad::logs::endpoint_security::writers {
class FileTest;
}

namespace santa::santad::logs::endpoint_security::writers {

class File : public Writer,
             public std::enable_shared_from_this<File> {
public:
  // Factory
  static std::shared_ptr<File> Create(NSString* path,
                                      uint64_t flush_timeout_ms,
                                      size_t batch_size_bytes,
                                      size_t max_expected_write_size_bytes);

  File(NSString* path,
       size_t batch_size_bytes,
       size_t max_expected_write_size_bytes,
       dispatch_queue_t q,
       dispatch_source_t timer_source);
  ~File();

  void Write(std::vector<uint8_t>&& bytes) override;

  friend class santa::santad::logs::endpoint_security::writers::FileTest;

private:
  void OpenFileHandle();
  void WatchLogFile();
  void FlushBuffer();

  std::vector<uint8_t> buffer_;
  size_t batch_size_bytes_;
  dispatch_queue_t q_;
  dispatch_source_t timer_source_;
  dispatch_source_t watch_source_;
  NSString *path_;
  NSFileHandle *file_handle_;
};

} // namespace santa::santad::logs::endpoint_security::writers

#endif
