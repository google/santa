#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include <EndpointSecurity/ESTypes.h>

#include <set>
#include <vector>

namespace santa::santad::event_providers::endpoint_security {

Client EndpointSecurityAPI::NewClient(
    void(^message_handler)(es_client_t*, Message)) {
  es_client_t *client = NULL;

  auto shared_es_api = shared_from_this();
  es_new_client_result_t res = es_new_client(&client, ^(es_client_t* c, const es_message_t* msg) {
    @autoreleasepool {
      message_handler(c, Message(shared_es_api, msg));
    }
  });

  return Client(client, res);
}

es_message_t* EndpointSecurityAPI::RetainMessage(const es_message_t* msg) {
  if (@available(macOS 11.0, *)) {
    es_retain_message(msg);
    es_message_t *nonconst = const_cast<es_message_t*>(msg);
    return nonconst;
  } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return es_copy_message(msg);
#pragma clang diagnostic pop
  }
}

void EndpointSecurityAPI::ReleaseMessage(es_message_t* msg) {
  if (@available(macOS 11.0, *)) {
    es_release_message(msg);
  } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return es_free_message(msg);
#pragma clang diagnostic pop
  }
}

bool EndpointSecurityAPI::Subscribe(const Client &client,
                                       std::set<es_event_type_t> event_types) {
  std::vector<es_event_type_t> subs(event_types.begin(), event_types.end());
  return es_subscribe(client.Get(), subs.data(), (uint32_t)subs.size()) ==
    ES_RETURN_SUCCESS;
}

bool EndpointSecurityAPI::RespondAuthResult(
    const Client &client,
    const Message& msg,
    es_auth_result_t result,
    bool cache) {
  return es_respond_auth_result(client.Get(), &(*msg), result, cache) ==
    ES_RESPOND_RESULT_SUCCESS;
}

bool EndpointSecurityAPI::MuteProcess(const Client &client,
                                      const audit_token_t* tok) {
  return es_mute_process(client.Get(), tok) == ES_RETURN_SUCCESS;
}

} // namespace santa::santad::event_providers::endpoint_security
