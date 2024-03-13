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

Message::Message(std::shared_ptr<EndpointSecurityAPI> esapi, const es_message_t *es_msg)
    : esapi_(std::move(esapi)), es_msg_(es_msg), process_token_(std::nullopt) {
  esapi_->RetainMessage(es_msg);
}

Message::~Message() {
  if (es_msg_) {
    esapi_->ReleaseMessage(es_msg_);
  }
}

Message::Message(Message &&other) {
  esapi_ = std::move(other.esapi_);
  es_msg_ = other.es_msg_;
  other.es_msg_ = nullptr;
  process_token_ = std::move(other.process_token_);
  other.process_token_ = std::nullopt;
}

Message::Message(const Message &other) {
  esapi_ = other.esapi_;
  es_msg_ = other.es_msg_;
  esapi_->RetainMessage(es_msg_);
  process_token_ = other.process_token_;
}

void Message::SetProcessToken(process_tree::ProcessToken tok) {
  process_token_ = std::move(tok);
}

std::string Message::ParentProcessName() const {
  return GetProcessName(es_msg_->process->ppid);
}

std::string Message::GetProcessName(pid_t pid) const {
  // Note: proc_name() accesses the `pbi_name` field of `struct proc_bsdinfo`. The size of `pname`
  // here is meant to match the size of `pbi_name`, and one extra byte ensure zero-terminated.
  char pname[MAXCOMLEN * 2 + 1] = {};
  if (proc_name(pid, pname, sizeof(pname)) > 0) {
    return std::string(pname);
  } else {
    return std::string("");
  }
}

}  // namespace santa::santad::event_providers::endpoint_security
