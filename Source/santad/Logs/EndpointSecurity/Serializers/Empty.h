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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_EMPTY_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_EMPTY_H

#include <memory>
#include <vector>

#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"

namespace santa::santad::logs::endpoint_security::serializers {

class Empty : public Serializer {
public:
  static std::shared_ptr<Empty> Create();

  std::vector<uint8_t> SerializeMessage(
      const santa::santad::event_providers::endpoint_security::EnrichedClose &) override;
  std::vector<uint8_t> SerializeMessage(
      const santa::santad::event_providers::endpoint_security::EnrichedExchange &) override;
  std::vector<uint8_t> SerializeMessage(
      const santa::santad::event_providers::endpoint_security::EnrichedExec &) override;
  std::vector<uint8_t> SerializeMessage(
      const santa::santad::event_providers::endpoint_security::EnrichedExit &) override;
  std::vector<uint8_t> SerializeMessage(
      const santa::santad::event_providers::endpoint_security::EnrichedFork &) override;
  std::vector<uint8_t> SerializeMessage(
      const santa::santad::event_providers::endpoint_security::EnrichedLink &) override;
  std::vector<uint8_t> SerializeMessage(
      const santa::santad::event_providers::endpoint_security::EnrichedRename &) override;
  std::vector<uint8_t> SerializeMessage(
      const santa::santad::event_providers::endpoint_security::EnrichedUnlink &) override;

  std::vector<uint8_t> SerializeAllowlist(
      const santa::santad::event_providers::endpoint_security::Message&,
      const std::string_view) override;

  std::vector<uint8_t> SerializeBundleHashingEvent(SNTStoredEvent*) override;

  std::vector<uint8_t> SerializeDiskAppeared(NSDictionary*) override;
  std::vector<uint8_t> SerializeDiskDisappeared(NSDictionary*) override;
};

} // namespace santa::santad::logs::endpoint_security::serializers

#endif
