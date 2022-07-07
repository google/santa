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
#ifndef SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_ENDPOINTSECURITYAPI_H
#define SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_ENDPOINTSECURITYAPI_H

#include <EndpointSecurity/EndpointSecurity.h>

#include <set>

#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

namespace santa::santad::event_providers::endpoint_security {

class EndpointSecurityAPI : public std::enable_shared_from_this<EndpointSecurityAPI> {
public:
  virtual ~EndpointSecurityAPI() = default;

  virtual Client NewClient(void(^message_handler)(es_client_t*, Message));

  virtual bool Subscribe(const Client &client,
                         const std::set<es_event_type_t>&);

  virtual es_message_t* RetainMessage(const es_message_t* msg);
  virtual void ReleaseMessage(es_message_t* msg);

  virtual bool RespondAuthResult(const Client &client,
                                 const Message& msg,
                                 es_auth_result_t result,
                                 bool cache);

  virtual bool MuteProcess(const Client &client, const audit_token_t* tok);

  virtual bool ClearCache(const Client &client);

private:
};

} // namespace santa::santad::event_providers::endpoint_security

#endif
