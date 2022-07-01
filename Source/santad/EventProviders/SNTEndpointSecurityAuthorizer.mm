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

#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"

#include <os/base.h>
#include <cstdlib>

#include <EndpointSecurity/ESTypes.h>

#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

#import "Source/common/SNTLogging.h"

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::logs::endpoint_security::Logger;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::event_providers::AuthResultCache;

@interface SNTEndpointSecurityAuthorizer()
@property SNTCompilerController* compilerController;
@property SNTExecutionController* execController;
@end

@implementation SNTEndpointSecurityAuthorizer {
  std::shared_ptr<Logger> _logger;
  std::shared_ptr<AuthResultCache> _authResultCache;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                       logger:(std::shared_ptr<Logger>)logger
               execController:(SNTExecutionController*)execController
           compilerController:(SNTCompilerController*)compilerController
              authResultCache:(std::shared_ptr<AuthResultCache>)authResultCache {
  self = [super initWithESAPI:esApi];
  if (self) {
    _logger = logger;
    _execController = execController;
    _compilerController = compilerController;
    _authResultCache = authResultCache;

    [self establishClient];
  }
  return self;
}

- (void)establishClient {
  [self establishClientOrDie:^(es_client_t *c, Message&& esMsg){
    if (unlikely(esMsg->event_type != ES_EVENT_TYPE_AUTH_EXEC)) {
      // This is a programming error
      LOGE(@"Atteempting to authorize a non-exec event");
      exit(EXIT_FAILURE);
    }

    // Automatically deny long file paths
    if (esMsg->event.exec.target->executable->path_truncated) {
      [self postAction:ACTION_RESPOND_DENY forMessage:esMsg];
      return;
    }

    [self processMessage:std::move(esMsg) handler:^(const Message& msg) {
      const es_file_t *target_file = msg->event.exec.target->executable;

      while (true) {
        auto returnAction = self->_authResultCache->CheckCache(target_file);
        if (RESPONSE_VALID(returnAction)) {
          bool cacheable = false;
          es_auth_result_t authResult = ES_AUTH_RESULT_DENY;

          switch (returnAction) {
            case ACTION_RESPOND_ALLOW_COMPILER:
              [self.compilerController setIsCompiler:msg->event.exec.target->audit_token];
              OS_FALLTHROUGH;
            case ACTION_RESPOND_ALLOW:
              cacheable = true;
              authResult = ES_AUTH_RESULT_ALLOW;
              break;
            default:
              break;
          }

          [self respondToMessage:msg withAuthResult:authResult cacheable:cacheable];
          return;
        } else if (returnAction == ACTION_REQUEST_BINARY) {
          // TODO(rah): Look at a replacement for msleep(), maybe NSCondition
          usleep(5000);
        } else {
          break;
        }
      }

      self->_authResultCache->AddToCache(target_file, ACTION_REQUEST_BINARY);

      [self.execController validateExecEvent:msg postAction:^bool(santa_action_t action){
        return [self postAction:action forMessage:msg];
      }];
    }];
  }];
}

- (bool)postAction:(santa_action_t)action forMessage:(const Message&)esMsg {
  es_auth_result_t authResult;

  switch (action) {
    case ACTION_RESPOND_ALLOW_COMPILER:
      [self.compilerController setIsCompiler:esMsg->process->audit_token];
      OS_FALLTHROUGH;
    case ACTION_RESPOND_ALLOW:
      authResult = ES_AUTH_RESULT_ALLOW;
      break;
    case ACTION_RESPOND_DENY:
      authResult = ES_AUTH_RESULT_DENY;
      break;
    default:
      // This is a programming error. Bail.
      LOGE(@"Invalid action for postAction, exiting.");
      exit(EXIT_FAILURE);
  }

  self->_authResultCache->AddToCache(esMsg->event.exec.target->executable,
                                     action);

  // Don't cache DENY results. Santa only flushes ES cache when a new DENY rule
  // is received. If DENY results were cached and a rule update made the
  // executable allowable, ES would continue to apply the DENY cached result.
  return [self respondToMessage:esMsg
                 withAuthResult:authResult
                      cacheable:(authResult == ES_AUTH_RESULT_ALLOW)];
}

- (void)enable {
  [super subscribe:{
      ES_EVENT_TYPE_AUTH_EXEC,
  }];

  // There's a gap between creating a client and subscribing to events. Creating the client
  // triggers a cache flush automatically but any events that happen in this gap could be allowed
  // and cached, so we force the cache to flush again.
  [self clearCache];
}

@end
