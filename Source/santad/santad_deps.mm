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

#include "Source/santad/santad_deps.h"

#include <memory>

using santa::santad::logs::endpoint_security::Logger;

namespace santa::santad {

std::unique_ptr<SantadDeps> SantadDeps::Create(
    id<SNTConfigurationProvider> config_provider) {

  return std::make_unique<SantadDeps>(
      Logger::Create([config_provider eventLogType],
                     [config_provider eventLogPath]));
}

SantadDeps::SantadDeps(std::unique_ptr<Logger> logger)
  : logger_(std::move(logger)) {}

std::shared_ptr<Logger> SantadDeps::logger() {
  return logger_;
}

} // namespace santa::santad
