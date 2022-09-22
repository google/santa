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
#ifndef SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_ENRICHER_H
#define SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_ENRICHER_H

#include <memory>

#include "Source/common/SantaCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"

namespace santa::santad::event_providers::endpoint_security {

class Enricher {
 public:
  Enricher();
  virtual ~Enricher() = default;
  virtual std::shared_ptr<EnrichedMessage> Enrich(Message &&msg);
  virtual EnrichedProcess Enrich(const es_process_t &es_proc);
  virtual EnrichedFile Enrich(const es_file_t &es_file);

  virtual std::optional<std::shared_ptr<std::string>> UsernameForUID(uid_t uid);
  virtual std::optional<std::shared_ptr<std::string>> UsernameForGID(gid_t gid);

 private:
  SantaCache<uid_t, std::optional<std::shared_ptr<std::string>>>
      username_cache_;
  SantaCache<gid_t, std::optional<std::shared_ptr<std::string>>>
      groupname_cache_;
};

}  // namespace santa::santad::event_providers::endpoint_security

#endif
