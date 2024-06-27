/// Copyright 2022 Google LLC
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

#ifndef SANTA__COMMON__PLATFORM_H
#define SANTA__COMMON__PLATFORM_H

#include <Availability.h>

#if defined(MAC_OS_VERSION_12_0) && \
    MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_VERSION_12_0
#define HAVE_MACOS_12 1
#else
#define HAVE_MACOS_12 0
#endif

#if defined(MAC_OS_VERSION_13_0) && \
    MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_VERSION_13_0
#define HAVE_MACOS_13 1
#else
#define HAVE_MACOS_13 0
#endif

#if defined(MAC_OS_VERSION_14_0) && \
    MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_VERSION_14_0
#define HAVE_MACOS_14 1
#else
#define HAVE_MACOS_14 0
#endif

#endif
