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
#include <string_view>

#import "Source/common/SNTConfigurator.h"
#import "Source/santad/SNTDecisionCache.h"

namespace es = santa::santad::event_providers::endpoint_security;

namespace santa {

Serializer::Serializer(SNTDecisionCache *decision_cache) : decision_cache_(decision_cache) {
  if ([[SNTConfigurator configurator] enableMachineIDDecoration]) {
    enabled_machine_id_ = true;
    machine_id_ = [[[SNTConfigurator configurator] machineID] UTF8String] ?: "";
  }
}

bool Serializer::EnabledMachineID() {
  return enabled_machine_id_;
}

std::string_view Serializer::MachineID() {
  return std::string_view(machine_id_);
};

std::vector<uint8_t> Serializer::SerializeMessageTemplate(const es::EnrichedExec &msg) {
  SNTCachedDecision *cd;
  if (msg->action_type == ES_ACTION_TYPE_NOTIFY &&
      msg->action.notify.result.auth == ES_AUTH_RESULT_ALLOW) {
    // For allowed execs, cached decision timestamps must be updated
    cd = [decision_cache_ resetTimestampForCachedDecision:msg->event.exec.target->executable->stat];
  } else {
    cd = [decision_cache_ cachedDecisionForFile:msg->event.exec.target->executable->stat];
  }

  return SerializeMessage(msg, cd);
}

};  // namespace santa
