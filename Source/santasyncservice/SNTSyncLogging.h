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

#import "Source/common/SNTLogging.h"

#ifdef __cplusplus
extern "C" {
#endif

void logSyncMessage(LogLevel level, NSString *format, ...)
  __attribute__((format(__NSString__, 2, 3)));

#ifdef __cplusplus
}
#endif

///
///  Send logs to the standard pipeline AND to any active sync listeners.
///  Intended for use by the syncservice to send logs back to santactl instances.
///  LOG*() and logSyncMessage() both end up using a va_list which is single use. We are calling
///  both routines in this macro so they each get a copy of __VA_ARGS__.
///
///  TODO(bur): SLOGD() is temporarily set to LOG_LEVEL_INFO. Once santactl sync supports the
///  --debug flag, move this back to LOG_LEVEL_DEBUG. These debug logs are helpful when
///  troubleshooting sync issues with users, so let's opt to always log them for now.
///
#define SLOGD(logFormat, ...)                                 \
  do {                                                        \
    LOGD(logFormat, ##__VA_ARGS__);                           \
    logSyncMessage(LOG_LEVEL_INFO, logFormat, ##__VA_ARGS__); \
  } while (0)
#define SLOGI(logFormat, ...)                                 \
  do {                                                        \
    LOGI(logFormat, ##__VA_ARGS__);                           \
    logSyncMessage(LOG_LEVEL_INFO, logFormat, ##__VA_ARGS__); \
  } while (0)
#define SLOGW(logFormat, ...)                                 \
  do {                                                        \
    LOGW(logFormat, ##__VA_ARGS__);                           \
    logSyncMessage(LOG_LEVEL_WARN, logFormat, ##__VA_ARGS__); \
  } while (0)
#define SLOGE(logFormat, ...)                                  \
  do {                                                         \
    LOGE(logFormat, ##__VA_ARGS__);                            \
    logSyncMessage(LOG_LEVEL_ERROR, logFormat, ##__VA_ARGS__); \
  } while (0)
