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

#ifndef SANTA__SANTAD__SANTAD_DEPS_H
#define SANTA__SANTAD__SANTAD_DEPS_H

#import <Foundation/Foundation.h>
#import <MOLXPCConnection/MOLXPCConnection.h>

#include <memory>

#include "Source/common/PrefixTree.h"
#include "Source/common/SNTConfigurator.h"
#import "Source/common/SNTMetricSet.h"
#include "Source/common/Unit.h"
#include "Source/santad/DataLayer/WatchItems.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/Metrics.h"
#include "Source/santad/ProcessTree/process_tree.h"
#import "Source/santad/SNTCompilerController.h"
#import "Source/santad/SNTExecutionController.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTSyncdQueue.h"
#include "Source/santad/TTYWriter.h"

namespace santa::santad {

class SantadDeps {
 public:
  static std::unique_ptr<SantadDeps> Create(SNTConfigurator *configurator,
                                            SNTMetricSet *metric_set);

  SantadDeps(
      std::shared_ptr<santa::santad::event_providers::endpoint_security::
                          EndpointSecurityAPI>
          esapi,
      std::unique_ptr<santa::santad::logs::endpoint_security::Logger> logger,
      std::shared_ptr<santa::santad::Metrics> metrics,
      std::shared_ptr<santa::santad::data_layer::WatchItems> watch_items,
      std::shared_ptr<santa::santad::event_providers::AuthResultCache>
          auth_result_cache,
      MOLXPCConnection *control_connection,
      SNTCompilerController *compiler_controller,
      SNTNotificationQueue *notifier_queue, SNTSyncdQueue *syncd_queue,
      SNTExecutionController *exec_controller,
      std::shared_ptr<santa::common::PrefixTree<santa::common::Unit>>
          prefix_tree,
      std::shared_ptr<santa::santad::TTYWriter> tty_writer,
      std::shared_ptr<process_tree::ProcessTree> process_tree);

  std::shared_ptr<santa::santad::event_providers::AuthResultCache>
  AuthResultCache();
  std::shared_ptr<santa::santad::event_providers::endpoint_security::Enricher>
  Enricher();
  std::shared_ptr<
      santa::santad::event_providers::endpoint_security::EndpointSecurityAPI>
  ESAPI();
  std::shared_ptr<santa::santad::logs::endpoint_security::Logger> Logger();
  std::shared_ptr<santa::santad::Metrics> Metrics();
  std::shared_ptr<santa::santad::data_layer::WatchItems> WatchItems();
  MOLXPCConnection *ControlConnection();
  SNTCompilerController *CompilerController();
  SNTNotificationQueue *NotifierQueue();
  SNTSyncdQueue *SyncdQueue();
  SNTExecutionController *ExecController();
  std::shared_ptr<santa::common::PrefixTree<santa::common::Unit>> PrefixTree();
  std::shared_ptr<santa::santad::TTYWriter> TTYWriter();
  std::shared_ptr<process_tree::ProcessTree> ProcessTree();

 private:
  std::shared_ptr<
      santa::santad::event_providers::endpoint_security::EndpointSecurityAPI>
      esapi_;
  std::shared_ptr<santa::santad::logs::endpoint_security::Logger> logger_;
  std::shared_ptr<santa::santad::Metrics> metrics_;
  std::shared_ptr<santa::santad::data_layer::WatchItems> watch_items_;
  std::shared_ptr<santa::santad::event_providers::endpoint_security::Enricher>
      enricher_;
  std::shared_ptr<santa::santad::event_providers::AuthResultCache>
      auth_result_cache_;

  MOLXPCConnection *control_connection_;
  SNTCompilerController *compiler_controller_;
  SNTNotificationQueue *notifier_queue_;
  SNTSyncdQueue *syncd_queue_;
  SNTExecutionController *exec_controller_;
  std::shared_ptr<santa::common::PrefixTree<santa::common::Unit>> prefix_tree_;
  std::shared_ptr<santa::santad::TTYWriter> tty_writer_;
  std::shared_ptr<process_tree::ProcessTree> process_tree_;
};

}  // namespace santa::santad

#endif
