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

#ifndef SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_CLIENT_H
#define SANTA__SANTAD__EVENTPROVIDERS_ENDPOINTSECURITY_CLIENT_H

#include <cstddef>

#import <EndpointSecurity/EndpointSecurity.h>

namespace santa::santad::event_providers::endpoint_security {

class Client {
public:
  explicit Client(es_client_t* client,
                  es_new_client_result_t result)
      : client_(client), result_(result) {}

  Client() : client_(nullptr), result_(ES_NEW_CLIENT_RESULT_ERR_INTERNAL) {}

  virtual ~Client() {
    if (client_) {
      // Special case: Not using EndpointSecurityAPI here due to circular refs.
      es_delete_client(client_);
    }
  }

  Client(Client&& other) {
    client_ = other.client_;
    result_ = other.result_;
    other.client_ = nullptr;
    other.result_ = ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
  }

  void operator=(Client&& rhs) {
    client_ = rhs.client_;
    result_ = rhs.result_;
    rhs.client_ = nullptr;
    rhs.result_ = ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
  }

  Client(const Client& other) = delete;
  void operator=(const Client& rhs) = delete;

  inline bool IsConnected() {
    return result_ == ES_NEW_CLIENT_RESULT_SUCCESS;
  }

  inline es_new_client_result_t NewClientResult() {
    return result_;
  }

  inline es_client_t* Get() const {
    return client_;
  }

private:
  es_client_t *client_;
  es_new_client_result_t result_;
};

} // namespace santa::santad::event_providers::endpoint_security

#endif
