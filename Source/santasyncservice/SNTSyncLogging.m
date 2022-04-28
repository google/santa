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

#import "Source/santasyncservice/SNTSyncLogging.h"
#include "Source/common/SNTLogging.h"

#import "Source/santasyncservice/SNTSyncBroadcaster.h"

void logSyncMessage(LogLevel level, NSString *format, ...) {
  static LogLevel logLevel = LOG_LEVEL_DEBUG;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    logLevel = EffectiveLogLevel();
  });
  if (logLevel < level) return;
  va_list args;
  va_start(args, format);
  NSMutableString *s = [[NSMutableString alloc] initWithFormat:format arguments:args];
  va_end(args);
  [[SNTSyncBroadcaster broadcaster] broadcastToLogListeners:s];
}
