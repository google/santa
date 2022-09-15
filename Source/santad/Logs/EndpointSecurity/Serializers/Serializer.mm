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

#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"

#include <EndpointSecurity/EndpointSecurity.h>

#import "Source/santad/SNTDecisionCache.h"

namespace es = santa::santad::event_providers::endpoint_security;

namespace santa::santad::logs::endpoint_security::serializers {

std::vector<uint8_t> Serializer::SerializeMessageTemplate(const es::EnrichedClose &msg) {
  return SerializeMessage(msg);
}
std::vector<uint8_t> Serializer::SerializeMessageTemplate(const es::EnrichedExchange &msg) {
  return SerializeMessage(msg);
}
std::vector<uint8_t> Serializer::SerializeMessageTemplate(const es::EnrichedExec &msg) {
  const es_message_t &es_msg = msg.es_msg();
  if (es_msg.action_type == ES_ACTION_TYPE_NOTIFY &&
      es_msg.action.notify.result.auth == ES_AUTH_RESULT_ALLOW) {
    // For allowed execs, cached decision timestamps must be updated
    [[SNTDecisionCache sharedCache]
      resetTimestampForCachedDecision:msg.es_msg().event.exec.target->executable->stat];
  }

  return SerializeMessage(msg);
}
std::vector<uint8_t> Serializer::SerializeMessageTemplate(const es::EnrichedExit &msg) {
  return SerializeMessage(msg);
}
std::vector<uint8_t> Serializer::SerializeMessageTemplate(const es::EnrichedFork &msg) {
  return SerializeMessage(msg);
}
std::vector<uint8_t> Serializer::SerializeMessageTemplate(const es::EnrichedLink &msg) {
  return SerializeMessage(msg);
}
std::vector<uint8_t> Serializer::SerializeMessageTemplate(const es::EnrichedRename &msg) {
  return SerializeMessage(msg);
}
std::vector<uint8_t> Serializer::SerializeMessageTemplate(const es::EnrichedUnlink &msg) {
  return SerializeMessage(msg);
}

};  // namespace santa::santad::logs::endpoint_security::serializers
