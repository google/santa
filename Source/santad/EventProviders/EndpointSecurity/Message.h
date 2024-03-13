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

#ifndef SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_MESSAGE_H
#define SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_MESSAGE_H

#include <EndpointSecurity/EndpointSecurity.h>

#include <memory>
#include <string>

#include "Source/santad/ProcessTree/process_tree.h"

namespace santa::santad::event_providers::endpoint_security {

class EndpointSecurityAPI;

class Message {
 public:
  Message(std::shared_ptr<EndpointSecurityAPI> esapi,
          const es_message_t* es_msg);
  ~Message();

  Message(Message&& other);
  // Note: Safe to implement this, just not currently needed so left deleted.
  Message& operator=(Message&& rhs) = delete;

  Message(const Message& other);
  Message& operator=(const Message& other) = delete;

  void SetProcessToken(process_tree::ProcessToken tok);

  // Operators to access underlying es_message_t
  const es_message_t* operator->() const { return es_msg_; }
  const es_message_t& operator*() const { return *es_msg_; }

  // Helper to get the API associated with this message.
  // Used for things like es_exec_arg_count.
  // We should ideally rework this to somehow present these functions as methods on the Message,
  // however this would be a bit of a bigger lift.
  std::shared_ptr<EndpointSecurityAPI> ESAPI() const { return esapi_; }

  std::string ParentProcessName() const;

 private:
  std::shared_ptr<EndpointSecurityAPI> esapi_;
  const es_message_t* es_msg_;
  std::optional<process_tree::ProcessToken> process_token_;

  std::string GetProcessName(pid_t pid) const;
};

}  // namespace santa::santad::event_providers::endpoint_security

#endif
