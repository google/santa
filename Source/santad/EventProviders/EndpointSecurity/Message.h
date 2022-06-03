#ifndef SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_MESSAGE_H
#define SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_MESSAGE_H

#include <memory>
#include <string>

#import <EndpointSecurity/EndpointSecurity.h>

namespace santa::santad::event_providers::endpoint_security {

class EndpointSecurityAPI;

class Message {
public:
  Message(std::shared_ptr<EndpointSecurityAPI> es_api,
                          const es_message_t* es_msg);
  ~Message();

  Message(const Message &other) = delete;
  Message& operator=(const Message &other) = delete;
  Message& operator=(Message &&rhs) = delete;

  Message(Message &&other);

  const es_message_t* operator->() const { return es_msg_; }
  const es_message_t& operator*() const { return *es_msg_; }

private:
  std::shared_ptr<EndpointSecurityAPI> es_api_;
  es_message_t* es_msg_;
};

} // namespace santa::santad::event_providers::endpoint_security

#endif
