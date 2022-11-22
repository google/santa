/// Copyright 2022 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include "Source/santad/EventProviders/SNTEndpointSecurityWatcher.h"

#include <EndpointSecurity/ESTypes.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <Kernel/kern/cs_blobs.h>
#include <sys/fcntl.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <memory>
#include <optional>
#include <set>
#include <type_traits>
#include <variant>

#include "Source/common/Unit.h"
#include "Source/santad/DataLayer/WatchItems.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

using santa::common::Unit;
using santa::santad::EventDisposition;
using santa::santad::data_layer::WatchItemPolicy;
using santa::santad::data_layer::WatchItems;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::Logger;

// Currently, all events used here have at least one target path that is represented
// by an `es_file_t` and this is held as the first pair item as an `std::string_view`
// since new memory isn't needed.
// For events that have a second target path, the `std::variant` will either be an
// `std::string_view` if possible, otherwise if a new string must be constructed an
// `std::string` is used.
using PathTargets = std::pair<std::string_view, std::variant<std::string_view, std::string, Unit>>;

static inline std::string_view PathView(const es_file_t *esFile) {
  return std::string_view(esFile->path.data, esFile->path.length);
}

static inline std::string_view PathView(const es_string_token_t &tok) {
  return std::string_view(tok.data, tok.length);
}

static inline std::string Path(const es_file_t *dir, const es_string_token_t &name) {
  return std::string(PathView(dir)) + std::string(PathView(name));
}

PathTargets GetPathTargets(const Message &msg) {
  switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_OPEN: return {PathView(msg->event.open.file), Unit{}};
    case ES_EVENT_TYPE_AUTH_LINK:
      return {PathView(msg->event.link.source),
              Path(msg->event.link.target_dir, msg->event.link.target_filename)};
    case ES_EVENT_TYPE_AUTH_RENAME:
      if (msg->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        return {PathView(msg->event.rename.source),
                PathView(msg->event.rename.destination.existing_file)};
      } else if (msg->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        return {PathView(msg->event.rename.source),
                Path(msg->event.rename.destination.new_path.dir,
                     msg->event.rename.destination.new_path.filename)};
      } else {
        [NSException raise:@"Unexpected destination type"
                    format:@"Rename event encountered with unexpected destination type: %d",
                           msg->event.rename.destination_type];
        exit(EXIT_FAILURE);
      }
    case ES_EVENT_TYPE_AUTH_UNLINK: return {PathView(msg->event.unlink.target), Unit{}};
    case ES_EVENT_TYPE_AUTH_CLONE:
      return {PathView(msg->event.clone.source),
              Path(msg->event.link.target_dir, msg->event.clone.target_name)};
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
      return {PathView(msg->event.exchangedata.file1), PathView(msg->event.exchangedata.file2)};
    case ES_EVENT_TYPE_AUTH_COPYFILE:
      if (msg->event.copyfile.target_file) {
        return {PathView(msg->event.copyfile.source), PathView(msg->event.copyfile.target_file)};
      } else {
        return {PathView(msg->event.copyfile.source),
                Path(msg->event.copyfile.target_dir, msg->event.copyfile.target_name)};
      }
    default:
      [NSException raise:@"Unexpected event type"
                  format:@"Watcher client does not handle event: %d", msg->event_type];
      exit(EXIT_FAILURE);
  }
}

@interface SNTEndpointSecurityWatcher ()
@property BOOL isSubscribed;
@end

@implementation SNTEndpointSecurityWatcher {
  std::shared_ptr<Logger> _logger;
  std::shared_ptr<WatchItems> _watchItems;
}

- (instancetype)
  initWithESAPI:
    (std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI>)esApi
        metrics:(std::shared_ptr<santa::santad::Metrics>)metrics
         logger:(std::shared_ptr<santa::santad::logs::endpoint_security::Logger>)logger
     watchItems:(std::shared_ptr<WatchItems>)watchItems {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:std::move(metrics)
                    processor:santa::santad::Processor::kWatcher];
  if (self) {
    _watchItems = std::move(watchItems);
    _logger = std::move(logger);

    [self establishClientOrDie];
  }
  return self;
}

- (NSString *)description {
  return @"Watcher";
}

// The operation is allowed when:
//   - No policy exists
//   - The policy is write-only, but the operation is read-only
//   - The operation was instigated by an allowed process
//   - If the instigating process is signed, the codesignature is valid
// Otherwise the operation is denied.
- (es_auth_result_t)getResponseForMessage:(const Message &)msg
                               withPolicy:
                                 (std::optional<std::shared_ptr<WatchItemPolicy>>)optionalPolicy {
  // If no policy exists, everything is allowed
  if (!optionalPolicy.has_value()) {
    return ES_AUTH_RESULT_ALLOW;
  }

  // If the process is signed but has an invalid signature, it is denied
  if ((msg->process->codesigning_flags & (CS_SIGNED | CS_VALID)) == CS_SIGNED) {
    // TODO(mlw): Think about how to make stronger guarantees here to handle
    // programs becoming invalid after first being granted access. Maybe we
    // should only allow things that have hardened runtime flags set?
    return ES_AUTH_RESULT_DENY;
  }

  std::shared_ptr<WatchItemPolicy> policy = optionalPolicy.value();

  constexpr int openFlagsIndicatingWrite = FWRITE | O_APPEND | O_TRUNC;

  switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_OPEN:
      // If the policy is write-only, but the operation isn't a write action, it's allowed
      if (policy->write_only && !(msg->event.open.fflag & openFlagsIndicatingWrite)) {
        return ES_AUTH_RESULT_ALLOW;
      }

      break;
    case ES_EVENT_TYPE_AUTH_LINK:
    case ES_EVENT_TYPE_AUTH_RENAME:
    case ES_EVENT_TYPE_AUTH_UNLINK:
    case ES_EVENT_TYPE_AUTH_CLONE:
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
    case ES_EVENT_TYPE_AUTH_COPYFILE:
      // TODO(xyz): Handle special cases for more event types
      break;
    default:
      [NSException raise:@"Unexpected event type"
                  format:@"Received unexpected event type in the watcher: %d", msg->event_type];
      exit(EXIT_FAILURE);
  }

  // Check if the instigating process has an allowed TeamID
  if (msg->process->team_id.data &&
      policy->allowed_team_ids.count(msg->process->team_id.data) > 0) {
    LOGE(@"Allowing TEAMID access to %s from %s (pid: %d) | policy: %s",
         msg->event.open.file->path.data, msg->process->executable->path.data,
         msg->process->audit_token.val[5], policy->name.c_str());
    return ES_AUTH_RESULT_ALLOW;
  }

  // Check if the instigating process path opening the file is allowed
  if (policy->allowed_binary_paths.count(msg->process->executable->path.data) > 0) {
    LOGE(@"Allowing PATH access to %s from %s (pid: %d) | policy: %s",
         msg->event.open.file->path.data, msg->process->executable->path.data,
         msg->process->audit_token.val[5], policy->name.c_str());
    return ES_AUTH_RESULT_ALLOW;
  }

  // TODO(xyz): Need to handle looking up `SNTCachedDecision`'s in decision cache
  // or to check `allowed_certificates_sha256`

  if (msg->process->codesigning_flags & CS_SIGNED) {
    std::array<uint8_t, CS_CDHASH_LEN> bytes;
    std::copy(std::begin(msg->process->cdhash), std::end(msg->process->cdhash), std::begin(bytes));
    if (policy->allowed_cdhashes.count(bytes) > 0) {
      LOGE(@"Allowing CDHASH access to %s from %s (pid: %d) | policy: %s",
           msg->event.open.file->path.data, msg->process->executable->path.data,
           msg->process->audit_token.val[5], policy->name.c_str());
      return ES_AUTH_RESULT_ALLOW;
    }
  }

  // If we get here, a policy existed and no exceptions were found. Log it.
  self->_logger->LogAccess(msg);

  // If the policy was audit-only, don't deny the operation
  if (policy->audit_only) {
    return ES_AUTH_RESULT_ALLOW;
  } else {
    // TODO(xyz): Write to TTY like in exec controller?
    // TODO(xyz): Need new config iitem for custom message in UI
    LOGE(@"Denying access to %s from %s (pid: %d) | policy: %s", msg->event.open.file->path.data,
         msg->process->executable->path.data, msg->process->audit_token.val[5],
         policy->name.c_str());
    return ES_AUTH_RESULT_DENY;
  }
}

- (void)processMessage:(const Message &)msg {
  PathTargets targets = GetPathTargets(msg);

  std::optional<std::shared_ptr<WatchItemPolicy>> policy1 =
    self->_watchItems->FindPolicyForPath(targets.first.data());

  std::shared_ptr<WatchItems> watchItems = self->_watchItems;
  std::optional<std::shared_ptr<WatchItemPolicy>> policy2 = std::visit(
    [&watchItems](const auto &arg) -> std::optional<std::shared_ptr<WatchItemPolicy>> {
      using T = std::decay_t<decltype(arg)>;
      if constexpr (std::is_same_v<T, std::string>) {
        return watchItems->FindPolicyForPath(arg.c_str());
      } else if constexpr (std::is_same_v<T, std::string_view>) {
        return watchItems->FindPolicyForPath(arg.data());
      } else {
        return std::nullopt;
      }
    },
    targets.second);

  es_auth_result_t policyResult1 = [self getResponseForMessage:msg withPolicy:policy1];
  es_auth_result_t policyResult2 = [self getResponseForMessage:msg withPolicy:policy2];

  // If either policy denied the operation, the operation is denied
  es_auth_result_t policyResult =
    ((policyResult1 == ES_AUTH_RESULT_DENY || policyResult2 == ES_AUTH_RESULT_DENY)
       ? ES_AUTH_RESULT_DENY
       : ES_AUTH_RESULT_ALLOW);

  [self respondToMessage:msg
          withAuthResult:policyResult
               cacheable:(policyResult == ES_AUTH_RESULT_ALLOW)];
}

- (void)handleMessage:(santa::santad::event_providers::endpoint_security::Message &&)esMsg
   recordEventMetrics:(void (^)(EventDisposition))recordEventMetrics {
  [self processMessage:std::move(esMsg)
               handler:^(const Message &msg) {
                 [self processMessage:msg];
                 recordEventMetrics(EventDisposition::kProcessed);
               }];
}

- (void)enable {
  // std::set<es_event_type_t> events{
  //   ES_EVENT_TYPE_AUTH_OPEN,
  //   ES_EVENT_TYPE_AUTH_LINK,
  //   ES_EVENT_TYPE_AUTH_RENAME,
  //   ES_EVENT_TYPE_AUTH_UNLINK,
  // };

  // if (@available(macOS 10.15.1, *)) {
  //   events.insert(ES_EVENT_TYPE_AUTH_CLONE);
  //   events.insert(ES_EVENT_TYPE_AUTH_EXCHANGEDATA);
  // }

  // if (@available(macOS 12.0, *)) {
  //   events.insert(ES_EVENT_TYPE_AUTH_COPYFILE);
  // }

  // [super subscribeAndClearCache:events];
  [super subscribeAndClearCache:{ES_EVENT_TYPE_AUTH_OPEN}];
}

@end
