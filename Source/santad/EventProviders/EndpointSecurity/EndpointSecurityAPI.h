#ifndef SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_ENDPOINTSECURITYAPI_H
#define SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_ENDPOINTSECURITYAPI_H

#include <set>

#include <EndpointSecurity/EndpointSecurity.h>

#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

namespace santa::santad::event_providers::endpoint_security {

class EndpointSecurityAPI : public std::enable_shared_from_this<EndpointSecurityAPI> {
public:
  virtual Client NewClient(void(^message_handler)(es_client_t*, Message));
  virtual ~EndpointSecurityAPI() = default;

  bool Subscribe(const Client &client, std::set<es_event_type_t>);

  virtual es_message_t* RetainMessage(const es_message_t* msg);
  virtual void ReleaseMessage(es_message_t* msg);

  virtual bool RespondAuthResult(const Client &client,
                                 const Message& msg,
                                 es_auth_result_t result,
                                 bool cache);

  virtual bool MuteProcess(const Client &client, const audit_token_t* tok);

private:
};

} // namespace santa::santad::event_providers::endpoint_security

#endif
