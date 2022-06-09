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

  _esClient = _esApi->NewClient(^(es_client_t *c, Message esMsg) {
    messageHandler(c, std::move(esMsg));
  });

  if (!_esClient.IsConnected()) {
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
