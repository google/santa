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

#import "Source/santad/EventProviders/SNTEndpointSecurityClient.h"

#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include <stdlib.h>

#import "Source/common/SNTLogging.h"

using santa::santad::event_providers::endpoint_security::Client;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Message;

@implementation SNTEndpointSecurityClient {
  std::shared_ptr<EndpointSecurityAPI> _esApi;
  Client _esClient;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi {
  self = [super init];
  if (self) {
    _esApi = esApi;
  }
  return self;
}

- (void)dealloc {
  // TODO: Check: Should be done automagically..
  //   * es_delete_client(_client)
}

- (void)establishClientOrDie:(void(^)(es_client_t *c, Message&& esMsg))messageHandler {
  if (self->_esClient.IsConnected()) {
    // This is a programming error
    LOGE(@"Client already established. Aborting.");
    exit(EXIT_FAILURE);
  }

  self->_esClient = self->_esApi->NewClient(^(es_client_t *c, Message esMsg) {
    messageHandler(c, std::move(esMsg));
  });

  if (!self->_esClient.IsConnected()) {
    switch(_esClient.NewClientResult()) {
      case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
        LOGE(@"Unable to create EndpointSecurity client, not full-disk access permitted");
      case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
        LOGE(@"Unable to create EndpointSecurity client, not entitled");
        break;
      case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
        LOGE(@"Unable to create EndpointSecurity client, not running as root");
        break;
      case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
        LOGE(@"Unable to create EndpointSecurity client, invalid argument");
        break;
      case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
        LOGE(@"Unable to create EndpointSecurity client, internal error");
        break;
      case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
        LOGE(@"Unable to create EndpointSecurity client, too many simultaneous clients");
        break;
      default:
        LOGE(@"Unable to create EndpointSecurity client, unknown error");
    }
    exit(EXIT_FAILURE);
  } else {
    LOGI(@"Connected to EndpointSecurity");
  }

  if (![self muteSelf]) {
    exit(EXIT_FAILURE);
  }
}

- (BOOL)muteSelf {
  audit_token_t myAuditToken;
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&myAuditToken, &count) ==
        KERN_SUCCESS) {
    if (self->_esApi->MuteProcess(self->_esClient, &myAuditToken)) {
      return YES;
    } else {
      LOGE(@"Failed to mute this client's process.");
    }
  } else {
    LOGE(@"Failed to fetch this client's audit token.");
  }

  return NO;
}

- (bool)subscribe:(std::set<es_event_type_t>)events {
  return _esApi->Subscribe(_esClient, events);
}

- (bool)respondToMessage:(const Message &)msg
          withAuthResult:(es_auth_result_t)result
               cacheable:(bool)cacheable {
  return _esApi->RespondAuthResult(_esClient, msg, result, cacheable);
}

@end
