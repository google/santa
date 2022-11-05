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

#include "Source/santad/SantadDeps.h"
#include <memory>

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#import "Source/santad/SNTDatabaseController.h"

using santa::common::PrefixTree;
using santa::common::Unit;
using santa::santad::Metrics;
using santa::santad::event_providers::AuthResultCache;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Enricher;
using santa::santad::logs::endpoint_security::Logger;

namespace santa::santad {

std::unique_ptr<SantadDeps> SantadDeps::Create(SNTConfigurator *configurator,
                                               SNTMetricSet *metric_set) {
  // TODO(mlw): The XPC interfaces should be injectable. Could either make a new
  // protocol defining appropriate methods or accept values as params.
  MOLXPCConnection *control_connection =
    [[MOLXPCConnection alloc] initServerWithName:[SNTXPCControlInterface serviceID]];
  if (!control_connection) {
    LOGE(@"Failed to initialize control connection.");
    exit(EXIT_FAILURE);
  }

  control_connection.privilegedInterface = [SNTXPCControlInterface controlInterface];
  control_connection.unprivilegedInterface = [SNTXPCUnprivilegedControlInterface controlInterface];

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
  if (!compiler_controller) {
    LOGE(@"Failed to initialize compiler controller.");
    exit(EXIT_FAILURE);
  }

  SNTNotificationQueue *notifier_queue = [[SNTNotificationQueue alloc] init];
  if (!notifier_queue) {
    LOGE(@"Failed to initialize notification queue.");
    exit(EXIT_FAILURE);
  }

  SNTSyncdQueue *syncd_queue = [[SNTSyncdQueue alloc] init];
  if (!syncd_queue) {
    LOGE(@"Failed to initialize syncd queue.");
    exit(EXIT_FAILURE);
  }

  SNTExecutionController *exec_controller =
    [[SNTExecutionController alloc] initWithRuleTable:rule_table
                                           eventTable:event_table
                                        notifierQueue:notifier_queue
                                           syncdQueue:syncd_queue];
  if (!exec_controller) {
    LOGE(@"Failed to initialize exec controller.");
    exit(EXIT_FAILURE);
  }

  std::shared_ptr<::PrefixTree<Unit>> prefix_tree = std::make_shared<::PrefixTree<Unit>>();

  // TODO(bur): Add KVO handling for fileChangesPrefixFilters.
  NSArray<NSString *> *prefix_filters =
    [@[ @"/.", @"/dev/" ] arrayByAddingObjectsFromArray:[configurator fileChangesPrefixFilters]];
  for (NSString *filter in prefix_filters) {
    prefix_tree->InsertPrefix([filter fileSystemRepresentation], Unit{});
  }

  std::shared_ptr<EndpointSecurityAPI> esapi = std::make_shared<EndpointSecurityAPI>();
  if (!esapi) {
    LOGE(@"Failed to create ES API wrapper.");
    exit(EXIT_FAILURE);
  }

  size_t spool_file_threshold_bytes = [configurator spoolDirectoryFileSizeThresholdKB] * 1024;
  size_t spool_dir_threshold_bytes = [configurator spoolDirectorySizeThresholdMB] * 1024 * 1024;
  uint64_t spool_flush_timeout_ms = [configurator spoolDirectoryEventMaxFlushTimeSec] * 1000;

  std::unique_ptr<::Logger> logger = Logger::Create(
    esapi, [configurator eventLogType], [configurator eventLogPath], [configurator spoolDirectory],
    spool_dir_threshold_bytes, spool_file_threshold_bytes, spool_flush_timeout_ms);
  if (!logger) {
    LOGE(@"Failed to create logger.");
    exit(EXIT_FAILURE);
  }

  std::shared_ptr<::Metrics> metrics =
    Metrics::Create(metric_set, [configurator metricExportInterval]);
  if (!metrics) {
    LOGE(@"Failed to create metrics");
    exit(EXIT_FAILURE);
  }

  return std::make_unique<SantadDeps>(esapi, metrics, std::move(logger), control_connection,
                                      compiler_controller, notifier_queue, syncd_queue,
                                      exec_controller, prefix_tree);
}

SantadDeps::SantadDeps(std::shared_ptr<EndpointSecurityAPI> esapi,
                       std::shared_ptr<::Metrics> metrics, std::unique_ptr<::Logger> logger,
                       MOLXPCConnection *control_connection,
                       SNTCompilerController *compiler_controller,
                       SNTNotificationQueue *notifier_queue, SNTSyncdQueue *syncd_queue,
                       SNTExecutionController *exec_controller,
                       std::shared_ptr<::PrefixTree<Unit>> prefix_tree)
    : esapi_(std::move(esapi)),
      logger_(std::move(logger)),
      metrics_(std::move(metrics)),
      enricher_(std::make_shared<::Enricher>()),
      auth_result_cache_(std::make_shared<::AuthResultCache>(esapi_)),
      control_connection_(control_connection),
      compiler_controller_(compiler_controller),
      notifier_queue_(notifier_queue),
      syncd_queue_(syncd_queue),
      exec_controller_(exec_controller),
      prefix_tree_(prefix_tree) {}

std::shared_ptr<::AuthResultCache> SantadDeps::AuthResultCache() {
  return auth_result_cache_;
}

std::shared_ptr<Enricher> SantadDeps::Enricher() {
  return enricher_;
}
std::shared_ptr<EndpointSecurityAPI> SantadDeps::ESAPI() {
  return esapi_;
}

std::shared_ptr<Logger> SantadDeps::Logger() {
  return logger_;
}

std::shared_ptr<::Metrics> SantadDeps::Metrics() {
  return metrics_;
}

MOLXPCConnection *SantadDeps::ControlConnection() {
  return control_connection_;
}

SNTCompilerController *SantadDeps::CompilerController() {
  return compiler_controller_;
}

SNTNotificationQueue *SantadDeps::NotifierQueue() {
  return notifier_queue_;
}

SNTSyncdQueue *SantadDeps::SyncdQueue() {
  return syncd_queue_;
}

SNTExecutionController *SantadDeps::ExecController() {
  return exec_controller_;
}

std::shared_ptr<PrefixTree<Unit>> SantadDeps::PrefixTree() {
  return prefix_tree_;
}

}  // namespace santa::santad
