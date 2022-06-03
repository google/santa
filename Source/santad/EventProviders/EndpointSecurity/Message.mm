#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"

namespace santa::santad::event_providers::endpoint_security {

Message::Message(std::shared_ptr<EndpointSecurityAPI> es_api,
                 const es_message_t* es_msg) : es_api_(es_api) {
  es_msg_ = es_api_->RetainMessage(es_msg);
}

Message::~Message() {
  if (es_msg_) {
    es_api_->ReleaseMessage(es_msg_);
  }
}

Message::Message(Message &&other) {
  es_api_ = std::move(other.es_api_);
  es_msg_ = other.es_msg_;
  other.es_msg_ = nullptr;
}

} // namespace santa::santad::event_providers::endpoint_security
