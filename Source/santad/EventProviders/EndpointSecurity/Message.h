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

#import <EndpointSecurity/EndpointSecurity.h>

#include <memory>
#include <string>

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

  // In macOS 10.15, es_retain_message/es_release_message were unsupported
  // and required a full copy, which impacts performance if done too much...
  Message(const Message& other);
  Message& operator=(const Message& other) = delete;

  // Operators to access underlying es_message_t
  const es_message_t* operator->() const { return es_msg_; }
  const es_message_t& operator*() const { return *es_msg_; }

  std::string ParentProcessName() const;

 private:
  std::shared_ptr<EndpointSecurityAPI> esapi_;
  es_message_t* es_msg_;

  mutable std::string pname_;
  mutable std::string parent_pname_;

  std::string GetProcessName(pid_t pid) const;
};

}  // namespace santa::santad::event_providers::endpoint_security

#endif
