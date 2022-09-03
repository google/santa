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

#include <EndpointSecurity/ESTypes.h>
#include <os/base.h>
#include <stdlib.h>

#import "Source/common/SNTLogging.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

using santa::santad::event_providers::AuthResultCache;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Message;

@interface SNTEndpointSecurityAuthorizer ()
@property SNTCompilerController *compilerController;
@property SNTExecutionController *execController;
@end

@implementation SNTEndpointSecurityAuthorizer {
  std::shared_ptr<AuthResultCache> _authResultCache;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
               execController:(SNTExecutionController *)execController
           compilerController:(SNTCompilerController *)compilerController
              authResultCache:(std::shared_ptr<AuthResultCache>)authResultCache {
  self = [super initWithESAPI:std::move(esApi)];
  if (self) {
    _execController = execController;
    _compilerController = compilerController;
    _authResultCache = authResultCache;

    [self establishClientOrDie];
  }
  return self;
}

- (void)processMessage:(const Message &)msg {
  const es_file_t *target_file = msg->event.exec.target->executable;

  while (true) {
    auto returnAction = self->_authResultCache->CheckCache(target_file);
    if (RESPONSE_VALID(returnAction)) {
      es_auth_result_t authResult = ES_AUTH_RESULT_DENY;

      switch (returnAction) {
        case ACTION_RESPOND_ALLOW_COMPILER:
          [self.compilerController setProcess:msg->event.exec.target->audit_token isCompiler:true];
          OS_FALLTHROUGH;
        case ACTION_RESPOND_ALLOW: authResult = ES_AUTH_RESULT_ALLOW; break;
        default: break;
      }

      [self respondToMessage:msg
              withAuthResult:authResult
                   cacheable:(authResult == ES_AUTH_RESULT_ALLOW)];
      return;
    } else if (returnAction == ACTION_REQUEST_BINARY) {
      // TODO(mlw): Look into caching a `Deferred<value>` to better prevent
      // raciness of multiple threads checking the cache simultaneously.
      // Also mitigates need to poll.
      usleep(5000);
    } else {
      break;
    }
  }

  self->_authResultCache->AddToCache(target_file, ACTION_REQUEST_BINARY);

  [self.execController validateExecEvent:msg
                              postAction:^bool(santa_action_t action) {
                                return [self postAction:action forMessage:msg];
                              }];
}

- (void)handleMessage:(Message &&)esMsg {
  if (unlikely(esMsg->event_type != ES_EVENT_TYPE_AUTH_EXEC)) {
    // This is a programming error
    LOGE(@"Atteempting to authorize a non-exec event");
    [NSException raise:@"Invalid event type"
                format:@"Authorizing unexpected event type: %d", esMsg->event_type];
  }

  if (![self.execController synchronousShouldProcessExecEvent:esMsg]) {
    [self postAction:ACTION_RESPOND_DENY forMessage:esMsg];
    return;
  }

  [self processMessage:std::move(esMsg)
               handler:^(const Message &msg) {
                 [self processMessage:msg];
               }];
}

- (bool)postAction:(santa_action_t)action forMessage:(const Message &)esMsg {
  es_auth_result_t authResult;

  switch (action) {
    case ACTION_RESPOND_ALLOW_COMPILER:
      [self.compilerController setProcess:esMsg->event.exec.target->audit_token isCompiler:true];
      OS_FALLTHROUGH;
    case ACTION_RESPOND_ALLOW: authResult = ES_AUTH_RESULT_ALLOW; break;
    case ACTION_RESPOND_DENY: authResult = ES_AUTH_RESULT_DENY; break;
    default:
      // This is a programming error. Bail.
      LOGE(@"Invalid action for postAction, exiting.");
      [NSException raise:@"Invalid post action" format:@"Invalid post action: %d", action];
  }

  self->_authResultCache->AddToCache(esMsg->event.exec.target->executable, action);

  // Don't cache DENY results. Santa only flushes ES cache when a new DENY rule
  // is received. If DENY results were cached and a rule update made the
  // executable allowable, ES would continue to apply the DENY cached result.
  return [self respondToMessage:esMsg
                 withAuthResult:authResult
                      cacheable:(authResult == ES_AUTH_RESULT_ALLOW)];
}

- (void)enable {
  [super subscribeAndClearCache:{
                                  ES_EVENT_TYPE_AUTH_EXEC,
                                }];
}

@end
