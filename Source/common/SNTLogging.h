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

///
/// Logging definitions, for both kernel and user space.
///

#ifndef SANTA__COMMON__LOGGING_H
#define SANTA__COMMON__LOGGING_H

#ifdef KERNEL

#include <IOKit/IOLib.h>

#ifdef DEBUG
#define LOGD(format, ...) IOLog("D santa-driver: " format "\n", ##__VA_ARGS__);
#else  // DEBUG
#define LOGD(format, ...)
#endif  // DEBUG
#define LOGI(format, ...) IOLog("I santa-driver: " format "\n", ##__VA_ARGS__);
#define LOGW(format, ...) IOLog("W santa-driver: " format "\n", ##__VA_ARGS__);
#define LOGE(format, ...) IOLog("E santa-driver: " format "\n", ##__VA_ARGS__);

#else  // KERNEL

#ifdef __cplusplus
extern "C" {
#endif

#import <Foundation/Foundation.h>

typedef enum : NSUInteger {
  LOG_LEVEL_ERROR,
  LOG_LEVEL_WARN,
  LOG_LEVEL_INFO,
  LOG_LEVEL_DEBUG
} LogLevel;

///
///  Logging function.
///  @param level one of the levels defined above
///  @param destination a FILE, generally stdout/stderr. If the file is closed, the log
///      will instead be sent to syslog.
///  @param format the printf style format string
///  @param ... the arguments to format.
///
void logMessage(LogLevel level, FILE *destination, NSString *format, ...)
    __attribute__((format(__NSString__, 3, 4)));

/// Simple logging macros
#define LOGD(logFormat, ...) logMessage(LOG_LEVEL_DEBUG, stdout, logFormat, ##__VA_ARGS__)
#define LOGI(logFormat, ...) logMessage(LOG_LEVEL_INFO, stdout, logFormat, ##__VA_ARGS__)
#define LOGW(logFormat, ...) logMessage(LOG_LEVEL_WARN, stderr, logFormat, ##__VA_ARGS__)
#define LOGE(logFormat, ...) logMessage(LOG_LEVEL_ERROR, stderr, logFormat, ##__VA_ARGS__)

#ifdef __cplusplus
} // extern C
#endif

#endif  // KERNEL

#endif  // SANTA__COMMON__LOGGING_H
