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

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <functional>
#include <string>

#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool_platform_specific.h"
#include "absl/strings/match.h"
#include "absl/strings/str_format.h"

namespace fsspool {

absl::string_view PathSeparator() { return "/"; }

bool IsAbsolutePath(absl::string_view path) {
  return absl::StartsWith(path, "/");
}

int Write(int fd, absl::string_view buf) {
  return ::write(fd, buf.data(), buf.size());
}

int Unlink(const char* pathname) { return unlink(pathname); }

int MkDir(const char* path, mode_t mode) { return mkdir(path, mode); }

bool StatIsDir(mode_t mode) { return S_ISDIR(mode); }

bool StatIsReg(mode_t mode) { return S_ISREG(mode); }

int Open(const char* filename, int flags, mode_t mode) {
  return open(filename, flags, mode);
}

int Close(int fd) { return close(fd); }

absl::Status IterateDirectory(
    const std::string& dir, std::function<void(const std::string&)> callback) {
  if (!IsDirectory(dir)) {
    return absl::InvalidArgumentError(
        absl::StrFormat("%s is not a directory", dir));
  }
  DIR* dp = opendir(dir.c_str());
  if (dp == nullptr) {
    return absl::ErrnoToStatus(errno, absl::StrCat("failed to open ", dir));
  }
  struct dirent* ep;
  while ((ep = readdir(dp)) != nullptr) {
    callback(ep->d_name);
  }
  closedir(dp);
  return absl::OkStatus();
}

}  // namespace fsspool
