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
#include <objc/NSObjCRuntime.h>

#include <memory>

#include "Source/common/SNTConfigurationProvider.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/metrics.h"

namespace santa::santad {

class SantadDeps {
public:
  static std::unique_ptr<SantadDeps> Create(
      id<SNTConfigurationProvider> config_provider);

  SantadDeps(
      NSUInteger metric_export_interval,
      std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> esapi,
      std::unique_ptr<santa::santad::logs::endpoint_security::Logger> logger);


  std::shared_ptr<santa::santad::event_providers::AuthResultCache> AuthResultCache();
  std::shared_ptr<santa::santad::event_providers::endpoint_security::Enricher> Enricher();
  std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> ESAPI();
  std::shared_ptr<santa::santad::logs::endpoint_security::Logger> Logger();
  std::shared_ptr<santa::santad::Metrics> Metrics();

private:
  std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> esapi_;
  std::shared_ptr<santa::santad::logs::endpoint_security::Logger> logger_;
  std::shared_ptr<santa::santad::Metrics> metrics_;
  std::shared_ptr<santa::santad::event_providers::endpoint_security::Enricher> enricher_;
  std::shared_ptr<santa::santad::event_providers::AuthResultCache> auth_result_cache_;
};

} // namespace santa::santad

#endif
