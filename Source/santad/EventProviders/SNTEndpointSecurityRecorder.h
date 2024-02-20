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

#import "Source/common/PrefixTree.h"
#import "Source/common/Unit.h"
#import "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityEventHandler.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityTreeAwareClient.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#import "Source/santad/Metrics.h"
#include "Source/santad/ProcessTree/tree.h"
#import "Source/santad/SNTCompilerController.h"

/// ES Client focused on subscribing to NOTIFY event variants with the intention of enriching
/// received messages and logging the information.
@interface SNTEndpointSecurityRecorder
    : SNTEndpointSecurityTreeAwareClient <SNTEndpointSecurityEventHandler>

- (instancetype)
       initWithESAPI:
         (std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI>)
           esApi
             metrics:(std::shared_ptr<santa::santad::Metrics>)metrics
              logger:(std::shared_ptr<santa::santad::logs::endpoint_security::Logger>)logger
            enricher:
              (std::shared_ptr<santa::santad::event_providers::endpoint_security::Enricher>)enricher
  compilerController:(SNTCompilerController *)compilerController
     authResultCache:
       (std::shared_ptr<santa::santad::event_providers::AuthResultCache>)authResultCache
          prefixTree:(std::shared_ptr<santa::common::PrefixTree<santa::common::Unit>>)prefixTree
         processTree:(std::shared_ptr<process_tree::ProcessTree>)processTree;

@end
