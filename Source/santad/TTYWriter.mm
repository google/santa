/// Copyright 2023 Google LLC
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

#include "Source/santad/TTYWriter.h"

#import "Source/common/SNTLogging.h"
#include "Source/common/String.h"

namespace santa::santad {

std::unique_ptr<TTYWriter> TTYWriter::Create() {
  dispatch_queue_t q = dispatch_queue_create_with_target(
    "com.google.santa.ttywriter", DISPATCH_QUEUE_SERIAL,
    dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));

  if (!q) {
    return nullptr;
  }

  return std::make_unique<TTYWriter>(q);
}

TTYWriter::TTYWriter(dispatch_queue_t q) : q_(q) {}

void TTYWriter::Write(const char *tty, NSString *msg) {
  dispatch_async(q_, ^{
    @autoreleasepool {
      int fd = open(tty, O_WRONLY | O_NOCTTY);
      if (fd == -1) {
        LOGW(@"Failed to open TTY for writing");
        return;
      }

      std::string_view str = santa::common::NSStringToUTF8StringView(msg);
      write(fd, str.data(), str.length());

      close(fd);
    }
  });
}

}  // namespace santa::santad
