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

#include "Source/santad/Santad.h"

#include <memory>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTKVOManager.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityDeviceManager.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityRecorder.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityTamperResistance.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/SNTDaemonControlController.h"

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

void SantadMain(std::shared_ptr<EndpointSecurityAPI> esapi, std::shared_ptr<Logger> logger,
                std::shared_ptr<Metrics> metrics, std::shared_ptr<Enricher> enricher,
                std::shared_ptr<AuthResultCache> auth_result_cache,
                MOLXPCConnection *control_connection, SNTCompilerController *compiler_controller,
                SNTNotificationQueue *notifier_queue, SNTSyncdQueue *syncd_queue,
                SNTExecutionController *exec_controller,
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
             withCustomMessage:([configurator remountUSBMode]
                                  ? [configurator remountUSBBlockMessage]
                                  : [configurator bannedUSBBlockMessage])];
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
    [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:esapi logger:logger];

  EstablishSyncServiceConnection(syncd_queue);

  NSArray<SNTKVOManager *> *kvoObservers = @[
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(clientMode)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   if ([oldValue longLongValue] == [newValue longLongValue]) {
                                     // Note: This case apparently can happen and if not checked
                                     // will result in excessive notification messages sent to the
                                     // user when calling `postClientModeNotification` below
                                     return;
                                   }

                                   SNTClientMode clientMode =
                                     (SNTClientMode)[newValue longLongValue];

                                   switch (clientMode) {
                                     case SNTClientModeLockdown:
                                       LOGI(@"Changed client mode to Lockdown, flushing cache.");
                                       auth_result_cache->FlushCache(FlushCacheMode::kAllCaches);
                                       break;
                                     case SNTClientModeMonitor:
                                       LOGI(@"Changed client mode to Monitor.");
                                       break;
                                     default: LOGW(@"Changed client mode to unknown value."); break;
                                   }

                                   [[notifier_queue.notifierConnection remoteObjectProxy]
                                     postClientModeNotification:clientMode];
                                 }],
    [[SNTKVOManager alloc]
      initWithObject:configurator
            selector:@selector(syncBaseURL)
                type:[NSURL class]
            callback:^(NSURL *oldValue, NSURL *newValue) {
              if ((!newValue && !oldValue) ||
                  ([newValue.absoluteString isEqualToString:oldValue.absoluteString])) {
                return;
              }

              if (newValue) {
                LOGI(@"Establishing a new sync service connection with SyncBaseURL: %@", newValue);
                [NSObject cancelPreviousPerformRequestsWithTarget:[SNTConfigurator configurator]
                                                         selector:@selector(clearSyncState)
                                                           object:nil];
                [[syncd_queue.syncConnection remoteObjectProxy] spindown];
                EstablishSyncServiceConnection(syncd_queue);
              } else {
                LOGI(@"SyncBaseURL removed, spinning down sync service");
                [[syncd_queue.syncConnection remoteObjectProxy] spindown];
                // Keep the syncState active for 10 min in case com.apple.ManagedClient is
                // flapping.
                [[SNTConfigurator configurator] performSelector:@selector(clearSyncState)
                                                     withObject:nil
                                                     afterDelay:600];
              }
            }],
    [[SNTKVOManager alloc]
      initWithObject:configurator
            selector:@selector(exportMetrics)
                type:[NSNumber class]
            callback:^(NSNumber *oldValue, NSNumber *newValue) {
              BOOL oldBool = [oldValue boolValue];
              BOOL newBool = [newValue boolValue];
              if (oldBool == NO && newBool == YES) {
                LOGI(@"metricsExport changed NO -> YES, starting to export metrics");
                metrics->StartPoll();
              } else if (oldBool == YES && newBool == NO) {
                LOGI(@"metricsExport changed YES -> NO, stopping export of metrics");
                metrics->StopPoll();
              }
            }],
    [[SNTKVOManager alloc]
      initWithObject:configurator
            selector:@selector(metricExportInterval)
                type:[NSNumber class]
            callback:^(NSNumber *oldValue, NSNumber *newValue) {
              uint64_t oldInterval = [oldValue unsignedIntValue];
              uint64_t newInterval = [newValue unsignedIntValue];
              LOGI(@"MetricExportInterval changed from %llu to %llu restarting export", oldInterval,
                   newInterval);
              metrics->SetInterval(newInterval);
            }],
    [[SNTKVOManager alloc]
      initWithObject:configurator
            selector:@selector(allowedPathRegex)
                type:[NSRegularExpression class]
            callback:^(NSRegularExpression *oldValue, NSRegularExpression *newValue) {
              if ((!newValue && !oldValue) ||
                  ([newValue.pattern isEqualToString:oldValue.pattern])) {
                return;
              }

              LOGI(@"Changed allowlist regex, flushing cache");
              auth_result_cache->FlushCache(FlushCacheMode::kAllCaches);
            }],
    [[SNTKVOManager alloc]
      initWithObject:configurator
            selector:@selector(blockedPathRegex)
                type:[NSRegularExpression class]
            callback:^(NSRegularExpression *oldValue, NSRegularExpression *newValue) {
              if ((!newValue && !oldValue) ||
                  ([newValue.pattern isEqualToString:oldValue.pattern])) {
                return;
              }

              LOGI(@"Changed denylist regex, flushing cache");
              auth_result_cache->FlushCache(FlushCacheMode::kAllCaches);
            }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(blockUSBMount)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   BOOL oldBool = [oldValue boolValue];
                                   BOOL newBool = [newValue boolValue];

                                   if (oldBool == newBool) {
                                     return;
                                   }

                                   LOGI(@"BlockUSBMount changed: %d -> %d", oldBool, newBool);
                                   device_client.blockUSBMount = newBool;
                                 }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(remountUSBMode)
                                     type:[NSArray class]
                                 callback:^(NSArray *oldValue, NSArray *newValue) {
                                   if (!oldValue && !newValue) {
                                     return;
                                   }

                                   // Ensure the arrays are composed of strings
                                   for (id element in oldValue) {
                                     if (![element isKindOfClass:[NSString class]]) {
                                       return;
                                     }
                                   }

                                   for (id element in newValue) {
                                     if (![element isKindOfClass:[NSString class]]) {
                                       return;
                                     }
                                   }

                                   if ([oldValue isEqualToArray:newValue]) {
                                     return;
                                   }

                                   LOGI(@"RemountArgs changed: %@ -> %@",
                                        [oldValue componentsJoinedByString:@","],
                                        [newValue componentsJoinedByString:@","]);
                                   device_client.remountArgs = newValue;
                                 }],
  ];

  // Make the compiler happy. The variable is only used to ensure proper lifetime
  // of the SNTKVOManager objects it contains.
  (void)kvoObservers;

  [monitor_client enable];
  [authorizer_client enable];
  [device_client enable];
  [tamper_client enable];

  [[NSRunLoop mainRunLoop] run];
}
