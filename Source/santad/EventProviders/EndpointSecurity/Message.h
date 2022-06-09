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

  std::string ProcessName() const;
  std::string ParentProcessName() const;

private:
  std::shared_ptr<EndpointSecurityAPI> es_api_;
  es_message_t* es_msg_;

  mutable std::string pname_;
  mutable std::string parent_pname_;

  std::string GetProcessName(pid_t pid) const;
};

} // namespace santa::santad::event_providers::endpoint_security

#endif
