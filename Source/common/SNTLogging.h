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
/// Logging definitions
///

#ifndef SANTA__COMMON__LOGGING_H
#define SANTA__COMMON__LOGGING_H

#import <os/log.h>

#define LOG_WITH_TYPE(type, fmt, ...) os_log_with_type(OS_LOG_DEFAULT, type, fmt, ##__VA_ARGS__)
#define LOGD(fmt, ...) LOG_WITH_TYPE(OS_LOG_TYPE_DEBUG, "D " fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) LOG_WITH_TYPE(OS_LOG_TYPE_INFO, "I " fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) LOG_WITH_TYPE(OS_LOG_TYPE_DEFAULT, "W " fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) LOG_WITH_TYPE(OS_LOG_TYPE_ERROR, "E " fmt, ##__VA_ARGS__)

#endif  // SANTA__COMMON__LOGGING_H
