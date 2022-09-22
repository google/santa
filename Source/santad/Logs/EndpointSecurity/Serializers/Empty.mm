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

#include "Source/santad/Logs/EndpointSecurity/Serializers/Empty.h"

using santa::santad::event_providers::endpoint_security::EnrichedClose;
using santa::santad::event_providers::endpoint_security::EnrichedExchange;
using santa::santad::event_providers::endpoint_security::EnrichedExec;
using santa::santad::event_providers::endpoint_security::EnrichedExit;
using santa::santad::event_providers::endpoint_security::EnrichedFork;
using santa::santad::event_providers::endpoint_security::EnrichedLink;
using santa::santad::event_providers::endpoint_security::EnrichedRename;
using santa::santad::event_providers::endpoint_security::EnrichedUnlink;
using santa::santad::event_providers::endpoint_security::Message;

namespace santa::santad::logs::endpoint_security::serializers {

std::shared_ptr<Empty> Empty::Create() {
  return std::make_shared<Empty>();
}

std::vector<uint8_t> Empty::SerializeMessage(const EnrichedClose &msg) {
  return {};
}

std::vector<uint8_t> Empty::SerializeMessage(const EnrichedExchange &msg) {
  return {};
}

std::vector<uint8_t> Empty::SerializeMessage(const EnrichedExec &msg) {
  return {};
}

std::vector<uint8_t> Empty::SerializeMessage(const EnrichedExit &msg) {
  return {};
}

std::vector<uint8_t> Empty::SerializeMessage(const EnrichedFork &msg) {
  return {};
}

std::vector<uint8_t> Empty::SerializeMessage(const EnrichedLink &msg) {
  return {};
}

std::vector<uint8_t> Empty::SerializeMessage(const EnrichedRename &msg) {
  return {};
}

std::vector<uint8_t> Empty::SerializeMessage(const EnrichedUnlink &msg) {
  return {};
}

std::vector<uint8_t> Empty::SerializeAllowlist(const Message &msg, const std::string_view hash) {
  return {};
}

std::vector<uint8_t> Empty::SerializeBundleHashingEvent(SNTStoredEvent *event) {
  return {};
}

std::vector<uint8_t> Empty::SerializeDiskAppeared(NSDictionary *props) {
  return {};
}

std::vector<uint8_t> Empty::SerializeDiskDisappeared(NSDictionary *props) {
  return {};
}

}  // namespace santa::santad::logs::endpoint_security::serializers
