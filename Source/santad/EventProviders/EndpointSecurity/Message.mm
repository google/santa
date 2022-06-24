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
  es_api_ = other.es_api_;
  es_msg_ = other.es_msg_;
  other.es_msg_ = nullptr;
}

Message::Message(const Message &other) {
  es_api_ = other.es_api_;
  es_msg_ = other.es_msg_;
  es_api_->RetainMessage(es_msg_);
}

Message& Message::operator=(const Message &other) {
  es_api_->ReleaseMessage(es_msg_);
  es_api_ = other.es_api_;
  es_msg_ = other.es_msg_;
  es_api_->RetainMessage(es_msg_);
  return *this;
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
