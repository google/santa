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

#include "Source/santad/santad.h"

#include <memory>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTPrefixTree.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTCompilerController.h"
#import "Source/santad/SNTDatabaseController.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityDeviceManager.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityRecorder.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityTamperResistance.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Syslog.h"
#import "Source/santad/SNTExecutionController.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTSyncdQueue.h"

using santa::santad::event_providers::AuthResultCache;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Enricher;
using santa::santad::logs::endpoint_security::serializers::BasicString;
using santa::santad::logs::endpoint_security::writers::Syslog;
using santa::santad::logs::endpoint_security::Logger;

// TODO: Change return type
// int SantadMain(std::shared_ptr<EndpointSecurityAPI> es_api) {
int SantadMain() {
  SNTConfigurator *configurator = [SNTConfigurator configurator];

  SNTRuleTable *rule_table = [SNTDatabaseController ruleTable];
  if (!rule_table) {
    LOGE(@"Failed to initialize rule table.");
    exit(EXIT_FAILURE);
  }

  SNTEventTable *event_table = [SNTDatabaseController eventTable];
  if (!event_table) {
    LOGE(@"Failed to initialize event table.");
    exit(EXIT_FAILURE);
  }

  SNTCompilerController *compiler_controller = [[SNTCompilerController alloc] init];
  SNTNotificationQueue *notifier_queue = [[SNTNotificationQueue alloc] init];
  SNTSyncdQueue *syncd_queue = [[SNTSyncdQueue alloc] init];

  SNTExecutionController *exec_controller = [[SNTExecutionController alloc]
      initWithRuleTable:rule_table
             eventTable:event_table
          notifierQueue:notifier_queue
             syncdQueue:syncd_queue];

  auto prefix_tree = std::make_shared<SNTPrefixTree>();

  // TODO(bur): Add KVO handling for fileChangesPrefixFilters.
  NSArray<NSString*> *filters =
      [@[ @"/.", @"/dev/" ]
          arrayByAddingObjectsFromArray:[configurator fileChangesPrefixFilters]];

  for (NSString *filter in filters) {
    prefix_tree->AddPrefix([filter fileSystemRepresentation]);
  }

  auto es_api = std::make_shared<EndpointSecurityAPI>();
  std::shared_ptr<Enricher> enricher = std::make_shared<Enricher>();
  auto logger = std::make_shared<Logger>(std::make_unique<BasicString>(),
                                         std::make_unique<Syslog>());

  auto auth_result_cache = std::make_shared<AuthResultCache>(es_api);

  SNTEndpointSecurityDeviceManager *device_client =
      [[SNTEndpointSecurityDeviceManager alloc] initWithESAPI:es_api
                                                       logger:logger
                                              authResultCache:auth_result_cache];

  device_client.blockUSBMount = [configurator blockUSBMount];
  device_client.remountArgs = [configurator remountUSBMode];
  device_client.deviceBlockCallback = ^(SNTDeviceEvent *event) {
      [[notifier_queue.notifierConnection remoteObjectProxy]
        postUSBBlockNotification:event
               withCustomMessage:([configurator remountUSBMode] ?
                                     [configurator bannedUSBBlockMessage] :
                                     [configurator remountUSBBlockMessage])];
    };

  SNTEndpointSecurityRecorder *monitor_client =
      [[SNTEndpointSecurityRecorder alloc] initWithESAPI:es_api
                                                  logger:logger
                                                enricher:enricher
                                      compilerController:compiler_controller
                                         authResultCache:auth_result_cache
                                              prefixTree:prefix_tree];

  SNTEndpointSecurityAuthorizer *authorizer_client =
      [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:es_api
                                                    logger:logger
                                            execController:exec_controller
                                        compilerController:compiler_controller
                                           authResultCache:auth_result_cache];

  SNTEndpointSecurityTamperResistance *tamper_client =
      [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:es_api
                                                          logger:logger];

  [monitor_client enable];
  [authorizer_client enable];
  [device_client enable];
  [tamper_client enable];

  return 0;
}
