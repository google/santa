/// Copyright 2015 Google Inc. All rights reserved.
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

#import "SNTLogging.h"

#ifdef DEBUG
static int logLevel = LOG_LEVEL_DEBUG;
#else
static int logLevel = LOG_LEVEL_INFO;  // default to info
#endif

void logMessage(int level, FILE *destination, NSString *format, ...) {
  static NSDateFormatter *dateFormatter;
  static NSString *binaryName;
  static dispatch_once_t pred;

  dispatch_once(&pred, ^{
      dateFormatter = [[NSDateFormatter alloc] init];
      [dateFormatter setTimeZone:[NSTimeZone timeZoneWithName:@"UTC"]];
      [dateFormatter setDateFormat:@"YYYY-MM-dd HH:mm:ss.SSS'Z"];

      binaryName = [[NSProcessInfo processInfo] processName];

      // If debug logging is enabled, the process must be restarted.
      if ([[[NSProcessInfo processInfo] arguments] containsObject:@"--debug"]) {
        logLevel = LOG_LEVEL_DEBUG;
      }
  });

  if (logLevel < level) return;

  va_list args;
  va_start(args, format);
  NSString *s = [[NSString alloc] initWithFormat:format arguments:args];
  va_end(args);

  // Only prepend timestamp, severity and binary name if stdout is not a TTY
  if (isatty(fileno(destination))) {
    fprintf(destination, "%s\n", [s UTF8String]);
  } else {
    NSString *levelName;
    switch (level) {
      case LOG_LEVEL_ERROR: levelName = @"E"; break;
      case LOG_LEVEL_WARN: levelName = @"W"; break;
      case LOG_LEVEL_INFO: levelName = @"I"; break;
      case LOG_LEVEL_DEBUG: levelName = @"D"; break;
    }

    fprintf(destination, "%s\n", [[NSString stringWithFormat:@"[%@] %@ %@: %@",
            [dateFormatter stringFromDate:[NSDate date]], levelName, binaryName, s] UTF8String]);
  }
}
