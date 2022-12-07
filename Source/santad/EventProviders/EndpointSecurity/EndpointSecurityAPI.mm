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

#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include <EndpointSecurity/ESTypes.h>

#include <set>
#include <vector>

namespace santa::santad::event_providers::endpoint_security {

Client EndpointSecurityAPI::NewClient(void (^message_handler)(es_client_t *, Message)) {
  es_client_t *client = NULL;

  auto shared_esapi = shared_from_this();
  es_new_client_result_t res = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
    @autoreleasepool {
      message_handler(c, Message(shared_esapi, msg));
    }
  });

  return Client(client, res);
}

void EndpointSecurityAPI::RetainMessage(const es_message_t *msg) {
  es_retain_message(msg);
}

void EndpointSecurityAPI::ReleaseMessage(const es_message_t *msg) {
  es_release_message(msg);
}

bool EndpointSecurityAPI::Subscribe(const Client &client,
                                    const std::set<es_event_type_t> &event_types) {
  std::vector<es_event_type_t> subs(event_types.begin(), event_types.end());
  return es_subscribe(client.Get(), subs.data(), (uint32_t)subs.size()) == ES_RETURN_SUCCESS;
}

bool EndpointSecurityAPI::RespondAuthResult(const Client &client, const Message &msg,
                                            es_auth_result_t result, bool cache) {
  return es_respond_auth_result(client.Get(), &(*msg), result, cache) == ES_RESPOND_RESULT_SUCCESS;
}

bool EndpointSecurityAPI::RespondFlagsResult(const Client &client, const Message &msg,
                                             uint32_t allowed_flags, bool cache) {
  return es_respond_flags_result(client.Get(), &(*msg), allowed_flags, cache);
}

bool EndpointSecurityAPI::MuteProcess(const Client &client, const audit_token_t *tok) {
  return es_mute_process(client.Get(), tok) == ES_RETURN_SUCCESS;
}

bool EndpointSecurityAPI::ClearCache(const Client &client) {
  return es_clear_cache(client.Get()) == ES_CLEAR_CACHE_RESULT_SUCCESS;
}

uint32_t EndpointSecurityAPI::ExecArgCount(const es_event_exec_t *event) {
  return es_exec_arg_count(event);
}

es_string_token_t EndpointSecurityAPI::ExecArg(const es_event_exec_t *event, uint32_t index) {
  return es_exec_arg(event, index);
}

uint32_t EndpointSecurityAPI::ExecEnvCount(const es_event_exec_t *event) {
  return es_exec_env_count(event);
}

es_string_token_t EndpointSecurityAPI::ExecEnv(const es_event_exec_t *event, uint32_t index) {
  return es_exec_env(event, index);
}

uint32_t EndpointSecurityAPI::ExecFDCount(const es_event_exec_t *event) {
  if (@available(macOS 11.0, *)) {
    return es_exec_fd_count(event);
  } else {
    return 0;
  }
}

const es_fd_t *EndpointSecurityAPI::ExecFD(const es_event_exec_t *event, uint32_t index) {
  if (@available(macOS 11.0, *)) {
    return es_exec_fd(event, index);
  } else {
    return NULL;
  }
}

}  // namespace santa::santad::event_providers::endpoint_security
