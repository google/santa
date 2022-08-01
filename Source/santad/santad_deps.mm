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
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"

using santa::santad::Metrics;
using santa::santad::event_providers::AuthResultCache;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Enricher;
using santa::santad::logs::endpoint_security::Logger;

namespace santa::santad {

std::unique_ptr<SantadDeps> SantadDeps::Create(
    id<SNTConfigurationProvider> config_provider) {

  return std::make_unique<SantadDeps>(
      [config_provider metricExportTimeout],
      std::make_shared<EndpointSecurityAPI>(),
      Logger::Create([config_provider eventLogType],
                     [config_provider eventLogPath]));
}

SantadDeps::SantadDeps(
    NSUInteger metric_export_interval,
    std::shared_ptr<EndpointSecurityAPI> esapi,
    std::unique_ptr<::Logger> logger)
    : esapi_(std::move(esapi)),
      logger_(std::move(logger)),
      metrics_(Metrics::Create(metric_export_interval)),
      enricher_(std::make_shared<::Enricher>()),
      auth_result_cache_(std::make_shared<::AuthResultCache>(esapi_)) {}


std::shared_ptr<::AuthResultCache> SantadDeps::AuthResultCache() {
  return auth_result_cache_;
}

std::shared_ptr<Enricher> SantadDeps::Enricher() {
  return enricher_;
}
std::shared_ptr<EndpointSecurityAPI> SantadDeps::ESAPI() {
  return esapi_;
}

std::shared_ptr<Logger> SantadDeps::Logger() {
  return logger_;
}

std::shared_ptr<santa::santad::Metrics> SantadDeps::Metrics() {
  return metrics_;
}

} // namespace santa::santad
