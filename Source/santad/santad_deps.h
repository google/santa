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

#ifndef SANTA__SANTAD__SANTAD_DEPS_H
#define SANTA__SANTAD__SANTAD_DEPS_H

#include <Foundation/Foundation.h>

#include <memory>

#include "Source/common/SNTConfigurationProvider.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"

namespace santa::santad {

class SantadDeps {
public:
  static std::unique_ptr<SantadDeps> Create(
      id<SNTConfigurationProvider> config_provider);

  SantadDeps(
      std::unique_ptr<santa::santad::logs::endpoint_security::Logger> logger);

  std::shared_ptr<santa::santad::logs::endpoint_security::Logger> logger();

private:
  std::shared_ptr<santa::santad::logs::endpoint_security::Logger> logger_;
};

} // namespace santa::santad

#endif
