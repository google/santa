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

#import "Source/santad/EventProviders/SNTEndpointSecurityTamperResistance.h"

#include <EndpointSecurity/ESTypes.h>
#include <bsm/libbsm.h>
#include <string.h>
#include <algorithm>

#import "Source/common/SNTLogging.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Metrics.h"

using santa::santad::EventDisposition;
using santa::santad::data_layer::WatchItemPathType;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::Logger;

static constexpr std::string_view kSantaKextIdentifier = "com.google.santa-driver";

@implementation SNTEndpointSecurityTamperResistance {
  std::shared_ptr<Logger> _logger;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<santa::santad::Metrics>)metrics
                       logger:(std::shared_ptr<Logger>)logger {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:std::move(metrics)
                    processor:santa::santad::Processor::kTamperResistance];
  if (self) {
    _logger = logger;

    [self establishClientOrDie];
  }
  return self;
}

- (NSString *)description {
  return @"Tamper Resistance";
}

- (void)handleMessage:(Message &&)esMsg
   recordEventMetrics:(void (^)(EventDisposition))recordEventMetrics {
  es_auth_result_t result = ES_AUTH_RESULT_ALLOW;
  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_AUTH_UNLINK: {
      if ([SNTEndpointSecurityTamperResistance
            isProtectedPath:esMsg->event.unlink.target->path.data]) {
        result = ES_AUTH_RESULT_DENY;
        LOGW(@"Preventing attempt to delete Santa databases!");
      }
      break;
    }

    case ES_EVENT_TYPE_AUTH_RENAME: {
      if ([SNTEndpointSecurityTamperResistance
            isProtectedPath:esMsg->event.rename.source->path.data]) {
        result = ES_AUTH_RESULT_DENY;
        LOGW(@"Preventing attempt to rename Santa databases!");
        break;
      }

      if (esMsg->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        if ([SNTEndpointSecurityTamperResistance
              isProtectedPath:esMsg->event.rename.destination.existing_file->path.data]) {
          result = ES_AUTH_RESULT_DENY;
          LOGW(@"Preventing attempt to overwrite Santa databases!");
          break;
        }
      }

      break;
    }

    case ES_EVENT_TYPE_AUTH_SIGNAL: {
      // Only block signals sent to us and not from launchd.
      if (audit_token_to_pid(esMsg->event.signal.target->audit_token) == getpid() &&
          audit_token_to_pid(esMsg->process->audit_token) != 1) {
        LOGW(@"Preventing attempt to kill Santa daemon");
        result = ES_AUTH_RESULT_DENY;
      }
      break;
    }

    case ES_EVENT_TYPE_AUTH_EXEC: {
      // When not running a debug build, prevent attempts to kill Santa
      // by launchctl commands.
#ifndef DEBUG
      result = ValidateLaunchctlExec(esMsg);
      if (result == ES_AUTH_RESULT_DENY) LOGW(@"Preventing attempt to kill Santa daemon");
#endif
      break;
    }

    case ES_EVENT_TYPE_AUTH_KEXTLOAD: {
      // TODO(mlw): Since we don't package the kext anymore, we should consider removing this.
      // TODO(mlw): Consider logging when kext loads are attempted.
      if (strcmp(esMsg->event.kextload.identifier.data, kSantaKextIdentifier.data()) == 0) {
        result = ES_AUTH_RESULT_DENY;
        LOGW(@"Preventing attempt to load Santa kext!");
      }
      break;
    }

    default:
      // Unexpected event type, this is a programming error
      [NSException raise:@"Invalid event type"
                  format:@"Invalid tamper resistance event type: %d", esMsg->event_type];
  }

  // Do not cache denied operations so that each tamper attempt is logged
  [self respondToMessage:esMsg withAuthResult:result cacheable:result == ES_AUTH_RESULT_ALLOW];

  // For this client, a processed event is one that was found to be violating anti-tamper policy
  recordEventMetrics(result == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                   : EventDisposition::kDropped);
}

- (void)enable {
  [super enableTargetPathWatching];

  // Get the set of protected paths
  std::set<std::string> protectedPaths = [SNTEndpointSecurityTamperResistance getProtectedPaths];

  // Iterate the set, and create a vector of literals to mute
  std::vector<std::pair<std::string, WatchItemPathType>> watchPaths;
  for (const auto &path : protectedPaths) {
    watchPaths.push_back({path, WatchItemPathType::kLiteral});
  }
  watchPaths.push_back({"/Library/SystemExtensions", WatchItemPathType::kPrefix});
  watchPaths.push_back({"/bin/launchctl", WatchItemPathType::kLiteral});

  // Begin watching the protected set
  [super muteTargetPaths:watchPaths];

  [super subscribeAndClearCache:{
                                  ES_EVENT_TYPE_AUTH_KEXTLOAD,
                                  ES_EVENT_TYPE_AUTH_SIGNAL,
                                  ES_EVENT_TYPE_AUTH_EXEC,
                                  ES_EVENT_TYPE_AUTH_UNLINK,
                                  ES_EVENT_TYPE_AUTH_RENAME,
                                }];
}

es_auth_result_t ValidateLaunchctlExec(const Message &esMsg) {
  es_string_token_t exec_path = esMsg->event.exec.target->executable->path;
  if (strncmp(exec_path.data, "/bin/launchctl", exec_path.length) != 0) {
    return ES_AUTH_RESULT_ALLOW;
  }

  // Ensure there are at least 2 arguments after the command
  std::shared_ptr<EndpointSecurityAPI> esApi = esMsg.ESAPI();
  uint32_t argCount = esApi->ExecArgCount(&esMsg->event.exec);
  if (argCount < 2) {
    return ES_AUTH_RESULT_ALLOW;
  }

  // Check for some allowed subcommands
  es_string_token_t arg = esApi->ExecArg(&esMsg->event.exec, 1);
  static const std::unordered_set<std::string> safe_commands{
    "blame",
    "help",
    "hostinfo",
    "list",
    "plist",
    "print",
    "procinfo",
  };
  if (safe_commands.find(std::string(arg.data, arg.length)) != safe_commands.end()) {
    return ES_AUTH_RESULT_ALLOW;
  }

  // Check whether com.google.santa.daemon is in the argument list.
  // launchctl no longer accepts PIDs to operate on.
  for (int i = 2; i < argCount; i++) {
    es_string_token_t arg = esApi->ExecArg(&esMsg->event.exec, i);
    if (strnstr(arg.data, "com.google.santa.daemon", arg.length) != NULL) {
      return ES_AUTH_RESULT_DENY;
    }
  }

  return ES_AUTH_RESULT_ALLOW;
}

@end
