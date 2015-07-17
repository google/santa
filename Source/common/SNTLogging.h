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

#ifdef DEBUG
#define LOGD(...) IOLog("D santa-driver: " __VA_ARGS__); IOLog("\n");
#else  // DEBUG
#define LOGD(...)
#endif  // DEBUG
#define LOGI(...) IOLog("I santa-driver: " __VA_ARGS__); IOLog("\n")
#define LOGW(...) IOLog("W santa-driver: " __VA_ARGS__); IOLog("\n")
#define LOGE(...) IOLog("E santa-driver: " __VA_ARGS__); IOLog("\n")

#else  // KERNEL

#define LOG_LEVEL_ERROR   1
#define LOG_LEVEL_WARN    2
#define LOG_LEVEL_INFO    3
#define LOG_LEVEL_DEBUG   4

///
///  Logging function.
///  @param level one of the levels defined above
///  @param destination a FILE, generally stdout/stderr. If the file is closed, the log
///      will instead be sent to syslog.
///  @param format the printf style format string
///  @param ... the arguments to format.
///
void logMessage(int level, FILE *destination, NSString *format, ...)
    __attribute__((format(__NSString__, 3, 4)));

/// Simple logging macros
#define LOGD(logFormat, ...) logMessage(LOG_LEVEL_DEBUG, stdout, logFormat, ##__VA_ARGS__)
#define LOGI(logFormat, ...) logMessage(LOG_LEVEL_INFO, stdout, logFormat, ##__VA_ARGS__)
#define LOGW(logFormat, ...) logMessage(LOG_LEVEL_WARN, stderr, logFormat, ##__VA_ARGS__)
#define LOGE(logFormat, ...) logMessage(LOG_LEVEL_ERROR, stderr, logFormat, ##__VA_ARGS__)

#endif  // KERNEL

#endif  // SANTA__COMMON__LOGGING_H
