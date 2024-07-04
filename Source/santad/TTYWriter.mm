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

#include <string.h>
#include <sys/errno.h>
#include <sys/param.h>

#import "Source/common/SNTLogging.h"
#include "Source/common/String.h"

namespace santa::santad {

std::unique_ptr<TTYWriter> TTYWriter::Create() {
  dispatch_queue_t q = dispatch_queue_create_with_target(
    "com.google.santa.ttywriter", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,
    dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));

  if (!q) {
    return nullptr;
  }

  return std::make_unique<TTYWriter>(q);
}

TTYWriter::TTYWriter(dispatch_queue_t q) : q_(q) {}

bool TTYWriter::CanWrite(const es_process_t *proc) {
  return proc && proc->tty && proc->tty->path.length > 0;
}

void TTYWriter::Write(const es_process_t *proc, NSString *msg) {
  if (!CanWrite(proc)) {
    return;
  }

  // Copy the data from the es_process_t so the ES message doesn't
  // need to be retained
  NSString *tty = santa::StringToNSString(proc->tty->path.data);

  dispatch_async(q_, ^{
    int fd = open(tty.UTF8String, O_WRONLY | O_NOCTTY);
    if (fd == -1) {
      LOGW(@"Failed to open TTY for writing: %s", strerror(errno));
      return;
    }

    std::string_view str = santa::NSStringToUTF8StringView(msg);
    write(fd, str.data(), str.length());

    close(fd);
  });
}

}  // namespace santa::santad
