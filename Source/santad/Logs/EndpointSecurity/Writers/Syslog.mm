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

#include "Source/santad/Logs/EndpointSecurity/Writers/Syslog.h"

#include <os/log.h>

namespace santa::santad::logs::endpoint_security::writers {

std::shared_ptr<Syslog> Syslog::Create() {
  return std::make_shared<Syslog>();
}

void Syslog::Write(std::vector<uint8_t> &&bytes) {
  os_log(OS_LOG_DEFAULT, "%{public}s", bytes.data());
}

void Syslog::Flush() {
  // Nothing to do here
}

}  // namespace santa::santad::logs::endpoint_security::writers
