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

#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"

#include <EndpointSecurity/ESTypes.h>
#include <bsm/libbsm.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>

#include <memory>
#include <optional>

#include "Source/common/SNTLogging.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"

namespace santa::santad::event_providers::endpoint_security {

Enricher::Enricher() : username_cache_(256), groupname_cache_(256) {}

std::unique_ptr<EnrichedMessage> Enricher::Enrich(Message &&es_msg) {
  // TODO(mlw): Consider potential design patterns that could help reduce memory usage under load
  // (such as maybe the flyweight pattern)
  switch (es_msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
      return std::make_unique<EnrichedMessage>(EnrichedClose(
        std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.close.target)));
    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
      return std::make_unique<EnrichedMessage>(EnrichedExchange(
        std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.exchangedata.file1),
        Enrich(*es_msg->event.exchangedata.file2)));
    case ES_EVENT_TYPE_NOTIFY_EXEC:
      return std::make_unique<EnrichedMessage>(EnrichedExec(
        std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.exec.target),
        (es_msg->version >= 2 && es_msg->event.exec.script)
          ? std::make_optional(Enrich(*es_msg->event.exec.script))
          : std::nullopt,
        (es_msg->version >= 3 && es_msg->event.exec.cwd)
          ? std::make_optional(Enrich(*es_msg->event.exec.cwd))
          : std::nullopt));
    case ES_EVENT_TYPE_NOTIFY_FORK:
      return std::make_unique<EnrichedMessage>(EnrichedFork(
        std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.fork.child)));
    case ES_EVENT_TYPE_NOTIFY_EXIT:
      return std::make_unique<EnrichedMessage>(
        EnrichedExit(std::move(es_msg), Enrich(*es_msg->process)));
    case ES_EVENT_TYPE_NOTIFY_LINK:
      return std::make_unique<EnrichedMessage>(
        EnrichedLink(std::move(es_msg), Enrich(*es_msg->process),
                     Enrich(*es_msg->event.link.source), Enrich(*es_msg->event.link.target_dir)));
    case ES_EVENT_TYPE_NOTIFY_RENAME: {
      if (es_msg->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        return std::make_unique<EnrichedMessage>(EnrichedRename(
          std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.rename.source),
          std::nullopt, Enrich(*es_msg->event.rename.destination.new_path.dir)));
      } else {
        return std::make_unique<EnrichedMessage>(EnrichedRename(
          std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.rename.source),
          Enrich(*es_msg->event.rename.destination.existing_file), std::nullopt));
      }
    }
    case ES_EVENT_TYPE_NOTIFY_UNLINK:
      return std::make_unique<EnrichedMessage>(EnrichedUnlink(
        std::move(es_msg), Enrich(*es_msg->process), Enrich(*es_msg->event.unlink.target)));
    default:
      // This is a programming error
      LOGE(@"Attempting to enrich an unhandled event type: %d", es_msg->event_type);
      exit(EXIT_FAILURE);
  }
}

EnrichedProcess Enricher::Enrich(const es_process_t &es_proc, EnrichOptions options) {
  return EnrichedProcess(UsernameForUID(audit_token_to_euid(es_proc.audit_token), options),
                         UsernameForGID(audit_token_to_egid(es_proc.audit_token), options),
                         UsernameForUID(audit_token_to_ruid(es_proc.audit_token), options),
                         UsernameForGID(audit_token_to_rgid(es_proc.audit_token), options),
                         Enrich(*es_proc.executable, options));
}

EnrichedFile Enricher::Enrich(const es_file_t &es_file, EnrichOptions options) {
  // TODO(mlw): Consider having the enricher perform file hashing. This will
  // make more sense if we start including hashes in more event types.
  return EnrichedFile(UsernameForUID(es_file.stat.st_uid, options),
                      UsernameForGID(es_file.stat.st_gid, options), std::nullopt);
}

std::optional<std::shared_ptr<std::string>> Enricher::UsernameForUID(uid_t uid,
                                                                     EnrichOptions options) {
  std::optional<std::shared_ptr<std::string>> username = username_cache_.get(uid);

  if (username.has_value()) {
    return username;
  } else if (options == EnrichOptions::kLocalOnly) {
    // If `kLocalOnly` option is set, do not attempt a lookup
    return std::nullopt;
  } else {
    struct passwd *pw = getpwuid(uid);
    if (pw) {
      username = std::make_shared<std::string>(pw->pw_name);
    } else {
      username = std::nullopt;
    }

    username_cache_.set(uid, username);

    return username;
  }
}

std::optional<std::shared_ptr<std::string>> Enricher::UsernameForGID(gid_t gid,
                                                                     EnrichOptions options) {
  std::optional<std::shared_ptr<std::string>> groupname = groupname_cache_.get(gid);

  if (groupname.has_value()) {
    return groupname;
  } else if (options == EnrichOptions::kLocalOnly) {
    // If `kLocalOnly` option is set, do not attempt a lookup
    return std::nullopt;
  } else {
    struct group *gr = getgrgid(gid);
    if (gr) {
      groupname = std::make_shared<std::string>(gr->gr_name);
    } else {
      groupname = std::nullopt;
    }

    groupname_cache_.set(gid, groupname);

    return groupname;
  }
}

}  // namespace santa::santad::event_providers::endpoint_security
