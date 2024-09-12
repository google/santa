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

#include <cstdlib>
#include <memory>

#include "Source/common/PrefixTree.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileAccessEvent.h"
#import "Source/common/SNTKVOManager.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#include "Source/santad/DataLayer/WatchItems.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityDeviceManager.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityFileAccessAuthorizer.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityRecorder.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityTamperResistance.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/SNTDaemonControlController.h"
#include "Source/santad/SNTDecisionCache.h"
#include "Source/santad/TTYWriter.h"

using santa::AuthResultCache;
using santa::EndpointSecurityAPI;
using santa::Enricher;
using santa::FlushCacheMode;
using santa::FlushCacheReason;
using santa::Logger;
using santa::Metrics;
using santa::PrefixTree;
using santa::TTYWriter;
using santa::Unit;
using santa::WatchItems;

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
                std::shared_ptr<Metrics> metrics, std::shared_ptr<santa::WatchItems> watch_items,
                std::shared_ptr<Enricher> enricher,
                std::shared_ptr<AuthResultCache> auth_result_cache,
                MOLXPCConnection *control_connection, SNTCompilerController *compiler_controller,
                SNTNotificationQueue *notifier_queue, SNTSyncdQueue *syncd_queue,
                SNTExecutionController *exec_controller,
                std::shared_ptr<santa::PrefixTree<santa::Unit>> prefix_tree,
                std::shared_ptr<TTYWriter> tty_writer,
                std::shared_ptr<santa::santad::process_tree::ProcessTree> process_tree) {
  SNTConfigurator *configurator = [SNTConfigurator configurator];

  SNTDaemonControlController *dc =
    [[SNTDaemonControlController alloc] initWithAuthResultCache:auth_result_cache
                                              notificationQueue:notifier_queue
                                                     syncdQueue:syncd_queue
                                                         logger:logger
                                                     watchItems:watch_items];

  control_connection.exportedObject = dc;
  [control_connection resume];

  if ([configurator exportMetrics]) {
    metrics->StartPoll();
  }

  SNTEndpointSecurityDeviceManager *device_client =
    [[SNTEndpointSecurityDeviceManager alloc] initWithESAPI:esapi
                                                    metrics:metrics
                                                     logger:logger
                                            authResultCache:auth_result_cache
                                              blockUSBMount:[configurator blockUSBMount]
                                             remountUSBMode:[configurator remountUSBMode]
                                         startupPreferences:[configurator onStartUSBOptions]];

  device_client.deviceBlockCallback = ^(SNTDeviceEvent *event) {
    [[notifier_queue.notifierConnection remoteObjectProxy]
      postUSBBlockNotification:event
             withCustomMessage:([configurator remountUSBMode]
                                  ? [configurator remountUSBBlockMessage]
                                  : [configurator bannedUSBBlockMessage])];
  };

  SNTEndpointSecurityRecorder *monitor_client =
    [[SNTEndpointSecurityRecorder alloc] initWithESAPI:esapi
                                               metrics:metrics
                                                logger:logger
                                              enricher:enricher
                                    compilerController:compiler_controller
                                       authResultCache:auth_result_cache
                                            prefixTree:prefix_tree
                                           processTree:process_tree];

  SNTEndpointSecurityAuthorizer *authorizer_client =
    [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:esapi
                                                 metrics:metrics
                                          execController:exec_controller
                                      compilerController:compiler_controller
                                         authResultCache:auth_result_cache];

  SNTEndpointSecurityTamperResistance *tamper_client =
    [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:esapi metrics:metrics logger:logger];

  if (@available(macOS 13.0, *)) {
    SNTEndpointSecurityFileAccessAuthorizer *access_authorizer_client =
      [[SNTEndpointSecurityFileAccessAuthorizer alloc] initWithESAPI:esapi
                                                             metrics:metrics
                                                              logger:logger
                                                          watchItems:watch_items
                                                            enricher:enricher
                                                       decisionCache:[SNTDecisionCache sharedCache]
                                                           ttyWriter:tty_writer];
    watch_items->RegisterClient(access_authorizer_client);

    access_authorizer_client.fileAccessBlockCallback =
      ^(SNTFileAccessEvent *event, NSString *customMsg, NSString *customURL, NSString *customText) {
        [[notifier_queue.notifierConnection remoteObjectProxy]
          postFileAccessBlockNotification:event
                            customMessage:customMsg
                                customURL:customURL
                               customText:customText];
      };
  }

  EstablishSyncServiceConnection(syncd_queue);

  NSMutableArray<SNTKVOManager *> *kvoObservers = [[NSMutableArray alloc] init];
  [kvoObservers addObjectsFromArray:@[
    [[SNTKVOManager alloc]
      initWithObject:configurator
            selector:@selector(clientMode)
                type:[NSNumber class]
            callback:^(NSNumber *oldValue, NSNumber *newValue) {
              if ([oldValue longLongValue] == [newValue longLongValue]) {
                // Note: This case apparently can happen and if not checked
                // will result in excessive notification messages sent to the
                // user when calling `postClientModeNotification` below
                return;
              }

              SNTClientMode clientMode = (SNTClientMode)[newValue longLongValue];

              switch (clientMode) {
                case SNTClientModeLockdown:
                  LOGI(@"Changed client mode to Lockdown, flushing cache.");
                  auth_result_cache->FlushCache(FlushCacheMode::kAllCaches,
                                                FlushCacheReason::kClientModeChanged);
                  break;
                case SNTClientModeMonitor: LOGI(@"Changed client mode to Monitor."); break;
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
              auth_result_cache->FlushCache(FlushCacheMode::kAllCaches,
                                            FlushCacheReason::kPathRegexChanged);
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
              auth_result_cache->FlushCache(FlushCacheMode::kAllCaches,
                                            FlushCacheReason::kPathRegexChanged);
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
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(staticRules)
                                     type:[NSDictionary class]
                                 callback:^(NSDictionary *oldValue, NSDictionary *newValue) {
                                   if ([oldValue isEqualToDictionary:newValue]) {
                                     return;
                                   }

                                   LOGI(@"StaticRules set has changed, flushing cache.");
                                   auth_result_cache->FlushCache(
                                     FlushCacheMode::kAllCaches,
                                     FlushCacheReason::kStaticRulesChanged);
                                 }],
    [[SNTKVOManager alloc]
      initWithObject:configurator
            selector:@selector(eventLogType)
                type:[NSNumber class]
            callback:^(NSNumber *oldValue, NSNumber *newValue) {
              NSInteger oldLogType = [oldValue integerValue];
              NSInteger newLogType = [newValue integerValue];

              if (oldLogType == newLogType) {
                return;
              }

              LOGW(@"EventLogType config changed (%ld --> %ld). Restarting...", oldLogType,
                   newLogType);

              dispatch_semaphore_t sema = dispatch_semaphore_create(0);

              dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
                logger->Flush();
                metrics->Export();

                dispatch_semaphore_signal(sema);
              });

              // Wait for a short amount of time for outstanding data to flush
              dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

              // Forcefully exit. The daemon will be restarted immediately.
              exit(EXIT_SUCCESS);
            }],
    [[SNTKVOManager alloc]
      initWithObject:configurator
            selector:@selector(entitlementsTeamIDFilter)
                type:[NSArray class]
            callback:^(NSArray<NSString *> *oldValue, NSArray<NSString *> *newValue) {
              if ((!oldValue && !newValue) || [oldValue isEqualToArray:newValue]) {
                return;
              }

              LOGI(@"EntitlementsTeamIDFilter changed. '%@' --> '%@'. Flushing caches.", oldValue,
                   newValue);

              // Get the value from the configurator since that method ensures proper structure
              [exec_controller
                updateEntitlementsTeamIDFilter:[configurator entitlementsTeamIDFilter]];

              // Clear the AuthResultCache, then clear the ES cache to ensure
              // future execs get SNTCachedDecision entitlement values filtered
              // with the new settings.
              auth_result_cache->FlushCache(FlushCacheMode::kAllCaches,
                                            FlushCacheReason::kEntitlementsTeamIDFilterChanged);
              [authorizer_client clearCache];
            }],
    [[SNTKVOManager alloc]
      initWithObject:configurator
            selector:@selector(entitlementsPrefixFilter)
                type:[NSArray class]
            callback:^(NSArray<NSString *> *oldValue, NSArray<NSString *> *newValue) {
              if ((!oldValue && !newValue) || [oldValue isEqualToArray:newValue]) {
                return;
              }

              LOGI(@"EntitlementsPrefixFilter changed. '%@' --> '%@'. Flushing caches.", oldValue,
                   newValue);

              // Get the value from the configurator since that method ensures proper structure
              [exec_controller
                updateEntitlementsPrefixFilter:[configurator entitlementsPrefixFilter]];

              // Clear the AuthResultCache, then clear the ES cache to ensure
              // future execs get SNTCachedDecision entitlement values filtered
              // with the new settings.
              auth_result_cache->FlushCache(FlushCacheMode::kAllCaches,
                                            FlushCacheReason::kEntitlementsPrefixFilterChanged);
              [authorizer_client clearCache];
            }],
  ]];

  if (@available(macOS 13.0, *)) {
    // Only watch file access auth keys on mac 13 and newer
    [kvoObservers addObjectsFromArray:@[
      [[SNTKVOManager alloc]
        initWithObject:configurator
              selector:@selector(fileAccessPolicyPlist)
                  type:[NSString class]
              callback:^(NSString *oldValue, NSString *newValue) {
                if ([configurator fileAccessPolicy]) {
                  // Ignore any changes to this key if fileAccessPolicy is set
                  return;
                }

                if ((oldValue && !newValue) || (newValue && ![oldValue isEqualToString:newValue])) {
                  LOGI(@"Filesystem monitoring policy config path changed: %@ -> %@", oldValue,
                       newValue);
                  watch_items->SetConfigPath(newValue);
                }
              }],
      [[SNTKVOManager alloc] initWithObject:configurator
                                   selector:@selector(fileAccessPolicy)
                                       type:[NSDictionary class]
                                   callback:^(NSDictionary *oldValue, NSDictionary *newValue) {
                                     if ((oldValue && !newValue) ||
                                         (newValue && ![oldValue isEqualToDictionary:newValue])) {
                                       LOGI(
                                         @"Filesystem monitoring policy embedded config changed");
                                       watch_items->SetConfig(newValue);
                                     }
                                   }],
    ]];
  }

  // Make the compiler happy. The variable is only used to ensure proper lifetime
  // of the SNTKVOManager objects it contains.
  (void)kvoObservers;

  if (process_tree) {
    if (absl::Status status = process_tree->Backfill(); !status.ok()) {
      std::string err = status.ToString();
      LOGE(@"Failed to backfill process tree: %@", @(err.c_str()));
    }
  }

  // IMPORTANT: ES will hold up third party execs until early boot clients make
  // their first subscription. Ensuring the `Authorizer` client is enabled first
  // means that the AUTH EXEC event is subscribed first and Santa can apply
  // execution policy appropriately.
  [authorizer_client enable];
  [tamper_client enable];
  if (@available(macOS 13.0, *)) {
    // Start monitoring any watched items
    // Note: This feature is only enabled on macOS 13.0+
    watch_items->BeginPeriodicTask();
  }
  [monitor_client enable];
  [device_client enable];

  [[NSRunLoop mainRunLoop] run];
}
