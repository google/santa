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

#include <EndpointSecurity/EndpointSecurity.h>

#include <memory>
#include <string>

#import <Foundation/Foundation.h>

#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

@protocol SNTEndpointSecurityClientBase

- (instancetype)initWithESAPI:
    (std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI>)esApi;

- (void)establishClientOrDie:
    (void(^)(es_client_t* c,
             santa::santad::event_providers::endpoint_security::Message&& esMsg))messageHandler;

- (bool)subscribe:(const std::set<es_event_type_t>&)events;

/// Clears the ES cache after setting subscriptions.
/// There's a gap between creating a client and subscribing to events. Creating
/// the client triggers a cache flush automatically but any events that happen
/// prior to subscribing could've been cached by another client. Clearing after
/// subscribing mitigates this posibility.
- (bool)subscribeAndClearCache:(const std::set<es_event_type_t>&)events;

- (bool)respondToMessage:(const santa::santad::event_providers::endpoint_security::Message&)msg
          withAuthResult:(es_auth_result_t)result
               cacheable:(bool)cacheable;

- (void)processMessage:(santa::santad::event_providers::endpoint_security::Message&&)msg
               handler:(void(^)(const santa::santad::event_providers::endpoint_security::Message&))messageHandler;

- (bool)clearCache;

- (bool)isDatabasePath:(const std::string_view)path;

@end
