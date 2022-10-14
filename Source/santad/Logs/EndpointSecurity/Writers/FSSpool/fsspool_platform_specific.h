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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOLPLATFORMSPECIFIC_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOLPLATFORMSPECIFIC_H

#include <functional>
#include <string>

#include "absl/strings/string_view.h"

namespace fsspool {

absl::string_view PathSeparator();
bool IsAbsolutePath(absl::string_view path);
bool IsDirectory(const std::string& d);
int Close(int fd);
int Open(const char* filename, int flags, mode_t mode);
int MkDir(const char* path, mode_t mode);
bool StatIsDir(mode_t mode);
bool StatIsReg(mode_t mode);
int Unlink(const char* pathname);
int Write(int fd, absl::string_view buf);

absl::Status IterateDirectory(const std::string& dir,
                              std::function<void(const std::string&)> callback);

}  // namespace fsspool

#endif  // SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOLPLATFORMSPECIFIC_H
