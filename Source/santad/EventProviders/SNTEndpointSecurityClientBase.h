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
#include <bsm/libbsm.h>

#include <memory>
#include <string>
#include <vector>

#import <Foundation/Foundation.h>

#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Metrics.h"

@protocol SNTEndpointSecurityClientBase

- (instancetype)
  initWithESAPI:
    (std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI>)esApi
        metrics:(std::shared_ptr<santa::santad::Metrics>)metrics
      processor:(santa::santad::Processor)processor;

/// @note If this fails to establish a new ES client via `es_new_client`, an exception is raised
/// that should terminate the program.
- (void)establishClientOrDie;

- (bool)subscribe:(const std::set<es_event_type_t> &)events;

/// Clears the ES cache after setting subscriptions.
/// There's a gap between creating a client and subscribing to events. Creating
/// the client triggers a cache flush automatically but any events that happen
/// prior to subscribing could've been cached by another client. Clearing after
/// subscribing mitigates this posibility.
- (bool)subscribeAndClearCache:(const std::set<es_event_type_t> &)events;

- (bool)unsubscribeAll;
- (bool)unmuteEverything;
- (bool)enableTargetPathWatching;
- (bool)muteTargetPaths:
  (const std::vector<std::pair<std::string, santa::santad::data_layer::WatchItemPathType>> &)paths;
- (bool)unmuteTargetPaths:
  (const std::vector<std::pair<std::string, santa::santad::data_layer::WatchItemPathType>> &)paths;

/// Responds to the Message with the given auth result
///
/// @param Message The wrapped es_message_t being responded to
/// @param result Either ES_AUTH_RESULT_ALLOW or ES_AUTH_RESULT_DENY
/// @param cacheable true if ES should attempt to cache the result, otherwise false
/// @return true if the response was successful, otherwise false
- (bool)respondToMessage:(const santa::santad::event_providers::endpoint_security::Message &)msg
          withAuthResult:(es_auth_result_t)result
               cacheable:(bool)cacheable;

- (void)
  processEnrichedMessage:
    (std::shared_ptr<santa::santad::event_providers::endpoint_security::EnrichedMessage>)msg
                 handler:
                   (void (^)(std::shared_ptr<
                             santa::santad::event_providers::endpoint_security::EnrichedMessage>))
                     messageHandler;

- (void)asynchronouslyProcess:(santa::santad::event_providers::endpoint_security::Message)msg
                      handler:
                        (void (^)(santa::santad::event_providers::endpoint_security::Message &&))
                          messageHandler;

- (void)processMessage:(santa::santad::event_providers::endpoint_security::Message &&)msg
               handler:
                 (void (^)(const santa::santad::event_providers::endpoint_security::Message &))
                   messageHandler;

- (bool)clearCache;

+ (bool)isDatabasePath:(const std::string_view)path;
+ (bool)populateAuditTokenSelf:(audit_token_t *)tok;

@end
