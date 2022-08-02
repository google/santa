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

#ifndef SANTA__SANTAD_SANTAD_H
#define SANTA__SANTAD_SANTAD_H

#import <MOLXPCConnection/MOLXPCConnection.h>

#include "Source/common/SNTPrefixTree.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/metrics.h"
#import "Source/santad/SNTCompilerController.h"
#import "Source/santad/SNTExecutionController.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTSyncdQueue.h"

void SantadMain(
    std::shared_ptr<santa::santad::event_providers::endpoint_security::EndpointSecurityAPI> esapi,
    std::shared_ptr<santa::santad::logs::endpoint_security::Logger> logger,
    std::shared_ptr<santa::santad::Metrics> metrics,
    std::shared_ptr<santa::santad::event_providers::endpoint_security::Enricher> enricher,
    std::shared_ptr<santa::santad::event_providers::AuthResultCache> auth_result_cache,
    MOLXPCConnection* control_connection,
    SNTCompilerController* compiler_controller,
    SNTNotificationQueue* notifier_queue,
    SNTSyncdQueue* syncd_queue,
    SNTExecutionController* exec_controller,
    std::shared_ptr<SNTPrefixTree> prefix_tree);

#endif
