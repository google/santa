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
#include "Source/santad/SNTDaemonControlController.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityDeviceManager.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityRecorder.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityTamperResistance.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"

using santa::santad::Metrics;
using santa::santad::event_providers::AuthResultCache;
using santa::santad::event_providers::FlushCacheMode;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Enricher;
using santa::santad::logs::endpoint_security::Logger;

static void EstablishSyncServiceConnection(SNTSyncdQueue *syncd_queue) {
  // The syncBaseURL check is here to stop retrying if the sync server is removed.
  if (![[SNTConfigurator configurator] syncBaseURL]) {
    return;
  }

  MOLXPCConnection *ss = [SNTXPCSyncServiceInterface configuredConnection];

  // This will handle retying connection establishment if there are issues with the service
  // during initialization (missing binary, malformed plist, bad code signature, etc.).
  // Once those issues are resolved the connection will establish.
  // This will also handle re-establishment if the service crashes or is killed.
  ss.invalidationHandler = ^(void) {
    syncd_queue.syncConnection.invalidationHandler = nil;
    dispatch_sync(dispatch_get_main_queue(), ^{
      EstablishSyncServiceConnection(syncd_queue);
    });
  };
  [ss resume];
  syncd_queue.syncConnection = ss;
}

void SantadMain(std::shared_ptr<EndpointSecurityAPI> esapi,
                std::shared_ptr<Logger> logger,
                std::shared_ptr<Metrics> metrics,
                std::shared_ptr<Enricher> enricher,
                std::shared_ptr<AuthResultCache> auth_result_cache,
                MOLXPCConnection* control_connection,
                SNTCompilerController* compiler_controller,
                SNTNotificationQueue* notifier_queue,
                SNTSyncdQueue* syncd_queue,
                SNTExecutionController* exec_controller,
                std::shared_ptr<SNTPrefixTree> prefix_tree) {
  SNTConfigurator *configurator = [SNTConfigurator configurator];

  SNTDaemonControlController *dc =
      [[SNTDaemonControlController alloc] initWithAuthResultCache:auth_result_cache
                                                notificationQueue:notifier_queue
                                                       syncdQueue:syncd_queue
                                                           logger:logger];

  control_connection.exportedObject = dc;
  [control_connection resume];

  if ([configurator exportMetrics]) {
    metrics->StartPoll();
  }

  SNTEndpointSecurityDeviceManager *device_client =
      [[SNTEndpointSecurityDeviceManager alloc] initWithESAPI:esapi
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
      [[SNTEndpointSecurityRecorder alloc] initWithESAPI:esapi
                                                  logger:logger
                                                enricher:enricher
                                      compilerController:compiler_controller
                                         authResultCache:auth_result_cache
                                              prefixTree:prefix_tree];

  SNTEndpointSecurityAuthorizer *authorizer_client =
      [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:esapi
                                            execController:exec_controller
                                        compilerController:compiler_controller
                                           authResultCache:auth_result_cache];

  SNTEndpointSecurityTamperResistance *tamper_client =
      [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:esapi];

  EstablishSyncServiceConnection(syncd_queue);

  // Begin observing config changes once everything is setup
  [configurator
      observeClientMode:^(SNTClientMode clientMode) {
        if (clientMode == SNTClientModeLockdown) {
          LOGI(@"Changed client mode to Lockdown, flushing cache.");
          auth_result_cache->FlushCache(FlushCacheMode::kAllCaches);
        } else if (clientMode == SNTClientModeMonitor) {
          LOGI(@"Changed client mode to Monitor.");
        } else {
          LOGW(@"Changed client mode to unknown value.");
        }

        [[notifier_queue.notifierConnection remoteObjectProxy]
            postClientModeNotification:clientMode];
      }
      syncBaseURL:^(NSURL* new_url) {
        if (new_url) {
          LOGI(@"Establishing a new sync service connection with SyncBaseURL: %@", new_url);
          [NSObject cancelPreviousPerformRequestsWithTarget:[SNTConfigurator configurator]
                                                  selector:@selector(clearSyncState)
                                                    object:nil];
          [[syncd_queue.syncConnection remoteObjectProxy] spindown];
          EstablishSyncServiceConnection(syncd_queue);
        } else {
          LOGI(@"SyncBaseURL removed, spinning down sync service");
          [[syncd_queue.syncConnection remoteObjectProxy] spindown];
          // Keep the syncState active for 10 min in case com.apple.ManagedClient is flapping.
          [[SNTConfigurator configurator] performSelector:@selector(clearSyncState)
                                              withObject:nil
                                              afterDelay:600];
        }
      }
      exportMetrics:^(BOOL old_val, BOOL new_val) {
        if (old_val == NO && new_val == YES) {
          LOGI(@"metricsExport changed NO -> YES, starting to export metrics");
          metrics->StartPoll();
        } else if (old_val == YES && new_val == NO) {
          LOGI(@"metricsExport changed YES -> NO, stopping export of metrics");
          metrics->StopPoll();
        }
      }
      metricExportInterval:^(NSUInteger old_val, NSUInteger new_val) {
        LOGI(@"MetricExportInterval changed from %ld to %ld restarting export",
             old_val,
             new_val);
        metrics->SetInterval(new_val);
      }
      allowedOrBlockedPathRegex:^() {
        LOGI(@"Changed [allow|deny]list regex, flushing cache");
        auth_result_cache->FlushCache(FlushCacheMode::kAllCaches);
      }
      blockUSBMount:^(BOOL old_val, BOOL new_val) {
        LOGI(@"BlockUSBMount changed: %d -> %d", old_val, new_val);
        device_client.blockUSBMount = new_val;
      }
      remountUSBMode:^(NSArray<NSString *>* old_val, NSArray<NSString *>* new_val) {
        LOGI(@"RemountArgs changed: %s -> %s",
             [[old_val componentsJoinedByString:@","] UTF8String],
             [[new_val componentsJoinedByString:@","] UTF8String]);
        device_client.remountArgs = new_val;
      }
  ];

  [monitor_client enable];
  [authorizer_client enable];
  [device_client enable];
  [tamper_client enable];
}
