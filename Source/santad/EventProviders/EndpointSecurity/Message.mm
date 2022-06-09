#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

#include <bsm/libbsm.h>
#include <libproc.h>

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

std::string Message::ProcessName() const {
  if (pname_.length() == 0) {
    pname_ = GetProcessName(audit_token_to_pid(es_msg_->process->audit_token));
  }
  return pname_;
}

std::string Message::ParentProcessName() const {
  if (parent_pname_.length() == 0) {
    parent_pname_ = GetProcessName(audit_token_to_pid(es_msg_->process->audit_token));
  }
  return parent_pname_;
}

std::string Message::GetProcessName(pid_t pid) const {
  char pname[MAXCOMLEN * 2 + 1] = {};
  if (proc_name(pid, pname, sizeof(pname)) > 0) {
    return std::string(pname);
  } else {
    return std::string("");
  }
}

} // namespace santa::santad::event_providers::endpoint_security
