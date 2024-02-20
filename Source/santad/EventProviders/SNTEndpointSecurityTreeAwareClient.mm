/// Copyright 2023 Google Inc. All rights reserved.
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

#import "Source/santad/EventProviders/SNTEndpointSecurityTreeAwareClient.h"

#include <EndpointSecurity/EndpointSecurity.h>

#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/ProcessTree/tree.h"
#include "Source/santad/ProcessTree/tree_darwin.h"
#include "Source/santad/ProcessTree/EndpointSecurityAdapter.h"
#include "Source/santad/Metrics.h"

using santa::santad::EventDisposition;
using santa::santad::Metrics;
using santa::santad::Processor;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Message;

@implementation SNTEndpointSecurityTreeAwareClient {
  int _processTreeClient;
  std::vector<bool> _addedEvents;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<Metrics>)metrics
                    processor:(Processor)processor
  processTree:(std::shared_ptr<process_tree::ProcessTree>)processTree {
  self = [super initWithESAPI:std::move(esApi) metrics:std::move(metrics) processor:processor];
  if (self) {
    _processTree = std::move(processTree);
    _processTreeClient = _processTree->RegisterClient();
    _addedEvents.resize(ES_EVENT_TYPE_LAST, false);
  }
  return self;
}

- (bool)subscribe:(const std::set<es_event_type_t> &)events {
  std::set<es_event_type_t> eventsWithLifecycle = events;
  if (events.find(ES_EVENT_TYPE_NOTIFY_FORK) == events.end()) {
    eventsWithLifecycle.insert(ES_EVENT_TYPE_NOTIFY_FORK);
    _addedEvents[ES_EVENT_TYPE_NOTIFY_FORK] = true;
  }
  if (events.find(ES_EVENT_TYPE_NOTIFY_EXEC) == events.end() && events.find(ES_EVENT_TYPE_AUTH_EXEC) == events.end()) {
    eventsWithLifecycle.insert(ES_EVENT_TYPE_NOTIFY_EXEC);
    _addedEvents[ES_EVENT_TYPE_NOTIFY_EXEC] = true;
  }
  if (events.find(ES_EVENT_TYPE_NOTIFY_EXIT) == events.end()) {
    eventsWithLifecycle.insert(ES_EVENT_TYPE_NOTIFY_EXIT);
    _addedEvents[ES_EVENT_TYPE_NOTIFY_EXIT] = true;
  }

  return [super subscribe:eventsWithLifecycle];
}

- (bool)handleContextMessage:(Message &)esMsg {
  // Inform the tree
  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_FORK:
    case ES_EVENT_TYPE_NOTIFY_EXEC:
    case ES_EVENT_TYPE_AUTH_EXEC:
    case ES_EVENT_TYPE_NOTIFY_EXIT:
      process_tree::InformFromESEvent(_processTreeClient, *_processTree, &*esMsg);
      break;
    default:
      break;
  }

  // Now enumerate the processes that processing this event might require access to...
  std::vector<struct process_tree::pid> pids;
  pids.emplace_back(process_tree::PidFromAuditToken(esMsg->process->audit_token));
  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC:
    case ES_EVENT_TYPE_NOTIFY_EXEC:
      pids.emplace_back(process_tree::PidFromAuditToken(esMsg->event.exec.target->audit_token));
      break;
    case ES_EVENT_TYPE_NOTIFY_FORK:
      pids.emplace_back(process_tree::PidFromAuditToken(esMsg->event.fork.child->audit_token));
      break;
    default:
      break;
  }

  // ...and create the token for those.
  esMsg.SetProcessToken(process_tree::ProcessToken(_processTree, std::move(pids)));

  return _addedEvents[esMsg->event_type];
}

@end
