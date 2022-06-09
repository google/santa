/// Copyright 2019 Google Inc. All rights reserved.
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

#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"

#include <bsm/libbsm.h>

#include <memory>

#include "Source/common/SNTLogging.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"

namespace santa::santad::event_providers::endpoint_security {

std::unique_ptr<EnrichedMessage> Enricher::Enrich(Message &&es_msg) {
  switch(es_msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_EXEC:
      return std::make_unique<EnrichedMessage>(
        EnrichedExec(
          std::move(es_msg),
          Enrich(*es_msg->process),
          Enrich(*es_msg->event.exec.target),
          (es_msg->version >= 2 && es_msg->event.exec.script) ?
            std::make_optional(Enrich(*es_msg->event.exec.script)) :
            std::nullopt,
          (es_msg->version >= 3) ? std::make_optional(Enrich(*es_msg->event.exec.cwd)) : std::nullopt));
    case ES_EVENT_TYPE_NOTIFY_FORK:
      return std::make_unique<EnrichedMessage>(
        EnrichedFork(std::move(es_msg),
                     Enrich(*es_msg->process),
                     Enrich(*es_msg->event.fork.child)));
    case ES_EVENT_TYPE_NOTIFY_EXIT:
      return std::make_unique<EnrichedMessage>(
        EnrichedExit(std::move(es_msg), Enrich(*es_msg->process)));
    default:
      // TODO: Metrics
      // This is a programming error
      LOGE(@"Attempting to enrich an unhandled event type: %d", es_msg->event_type);
      exit(EXIT_FAILURE);
  }
}

EnrichedProcess Enricher::Enrich(const es_process_t &es_proc) {
  return EnrichedProcess(
      UsernameForUID(audit_token_to_euid(es_proc.audit_token)),
      UsernameForGID(audit_token_to_egid(es_proc.audit_token)),
      UsernameForUID(audit_token_to_ruid(es_proc.audit_token)),
      UsernameForGID(audit_token_to_rgid(es_proc.audit_token)),
      Enrich(*es_proc.executable));
}

EnrichedFile Enricher::Enrich(const es_file_t &es_file) {
    return EnrichedFile(
        UsernameForUID(es_file.stat.st_uid),
        UsernameForGID(es_file.stat.st_gid),
        std::nullopt /* TODO: hash */);
}

std::optional<std::shared_ptr<std::string>> Enricher::UsernameForUID(uid_t uid) {
  return std::nullopt;
}
std::optional<std::shared_ptr<std::string>> Enricher::UsernameForGID(gid_t gid) {
  return std::nullopt;
}

} // namespace santa::santad::event_providers::endpoint_security
