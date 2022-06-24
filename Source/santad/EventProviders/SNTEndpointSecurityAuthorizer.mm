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

#import "Source/common/SantaCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

#import "Source/common/SNTLogging.h"

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::logs::endpoint_security::Logger;
using santa::santad::event_providers::endpoint_security::Message;

@interface SNTEndpointSecurityAuthorizer()
@property SNTCompilerController* compilerController;
@property SNTExecutionController* execController;
@end

@implementation SNTEndpointSecurityAuthorizer {
  std::shared_ptr<Logger> _logger;
  SantaCache<santa_vnode_id_t, uint64_t> *_rootDecisionCache;
  SantaCache<santa_vnode_id_t, uint64_t> *_nonRootDecisionCache;
  uint64_t _rootVnodeID;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                       logger:(std::shared_ptr<Logger>)logger
               execController:(SNTExecutionController*)execController
           compilerController:(SNTCompilerController*)compilerController {
  self = [super initWithESAPI:esApi];
  if (self) {
    _logger = logger;
    _execController = execController;
    _compilerController = compilerController;

    _rootDecisionCache = new SantaCache<santa_vnode_id_t, uint64_t>();
    _nonRootDecisionCache = new SantaCache<santa_vnode_id_t, uint64_t>();

    // Store the filesystem ID of the root vnode for split-cache usage.
    // If the stat fails for any reason _rootVnodeID will be 0 and all decisions will be in a single cache.
    struct stat rootStat;
    if (stat("/", &rootStat) == 0) {
      _rootVnodeID = (uint64_t)rootStat.st_dev;
    }

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

    [self processMessage:std::move(esMsg) handler:^(const Message& msg){
      [self.execController validateExecEvent:msg postAction:^int(santa_action_t action){
        return [self postAction:action forMessage:msg];
      }];
    }];
  }];
}

// TODO: Return type
- (int)postAction:(santa_action_t)action forMessage:(const Message&)esMsg {
  es_auth_result_t authResult;
  bool cacheable;
  switch (action) {
    case ACTION_RESPOND_ALLOW_COMPILER:
      [self.compilerController setIsCompiler:esMsg->process->audit_token];
      authResult = ES_AUTH_RESULT_ALLOW;
      // TODO: Why false?
      cacheable = false;
      [self.compilerController setIsCompiler:esMsg->process->audit_token];
      break;
    case ACTION_RESPOND_ALLOW:
    case ACTION_RESPOND_ALLOW_PENDING_TRANSITIVE:
      authResult = ES_AUTH_RESULT_ALLOW;
      cacheable = true;
      // TODO: Cache
      break;
    case ACTION_RESPOND_DENY:
      // TODO: Cache
      OS_FALLTHROUGH;
    case ACTION_RESPOND_TOOLONG:
      authResult = ES_AUTH_RESULT_DENY;
      // TODO: Why false? We should just clear caches on rule updates.
      // Note: Still would get NOTIFY event if want to log attempts
      cacheable = false;
      break;
    default:
      // This is a programming error. Bail.
      LOGE(@"Invalid action, exiting.");
      exit(EXIT_FAILURE);
  }

  return [self respondToMessage:esMsg withAuthResult:authResult cacheable:cacheable];
}

- (void)enable {
  [super subscribe:{
      ES_EVENT_TYPE_AUTH_EXEC,
  }];
}

@end
