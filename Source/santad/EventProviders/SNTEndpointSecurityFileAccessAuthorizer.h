/// Copyright 2022 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import <Foundation/Foundation.h>

#include <memory>

#include "Source/santad/DataLayer/WatchItems.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityClient.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityEventHandler.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/Metrics.h"
#import "Source/santad/SNTDecisionCache.h"

@interface SNTEndpointSecurityFileAccessAuthorizer
    : SNTEndpointSecurityClient <SNTEndpointSecurityEventHandler>

- (instancetype)
  initWithESAPI:
    (std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI>)esApi
        metrics:(std::shared_ptr<santa::santad::Metrics>)metrics
         logger:(std::shared_ptr<santa::santad::logs::endpoint_security::Logger>)logger
     watchItems:(std::shared_ptr<santa::santad::data_layer::WatchItems>)watchItems
  decisionCache:(SNTDecisionCache *)decisionCache;

@end
