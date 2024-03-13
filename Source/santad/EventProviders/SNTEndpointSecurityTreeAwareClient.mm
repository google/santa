/// Copyright 2024 Google LLC
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

#import "Source/santad/EventProviders/SNTEndpointSecurityTreeAwareClient.h"

#include <EndpointSecurity/EndpointSecurity.h>

#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/ProcessTree/process_tree.h"
#include "Source/santad/ProcessTree/process_tree_macos.h"
#include "Source/santad/ProcessTree/SNTEndpointSecurityAdapter.h"
#include "Source/santad/Metrics.h"

using santa::santad::EventDisposition;
using santa::santad::Metrics;
using santa::santad::Processor;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Message;

@implementation SNTEndpointSecurityTreeAwareClient {
  std::vector<bool> _addedEvents;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<Metrics>)metrics
                    processor:(Processor)processor
  processTree:(std::shared_ptr<santa::santad::process_tree::ProcessTree>)processTree {
  self = [super initWithESAPI:std::move(esApi) metrics:std::move(metrics) processor:processor];
  if (self) {
    _processTree = std::move(processTree);
    _addedEvents.resize(ES_EVENT_TYPE_LAST, false);
  }
  return self;
}

// ES guarantees logical consistency within a client (e.g. forks always preceed exits),
// however there are no guarantees about the ordering of when messages are delivered _across_ clients,
// meaning any client might be the first one to receive process events, and therefore
// would need to be the one to inform the tree.
// However not all clients are interested in or subscribe to process events.
// This (and the below handleContextMessage) ensures that the ES subscription for all clients includes
// the minimal required set of events for process tree (NOTIFY_FORK, some EXEC variant, and NOTIFY_EXIT)
// but also filters out any events that were subscribed to solely for the purpose of updating
// the tree from being processed downstream, where they would be unexpected.
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
  if (!_processTree) {
    return false;
  }

  // Inform the tree
  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_FORK:
    case ES_EVENT_TYPE_NOTIFY_EXEC:
    case ES_EVENT_TYPE_AUTH_EXEC:
    case ES_EVENT_TYPE_NOTIFY_EXIT:
      santa::santad::process_tree::InformFromESEvent(*_processTree, esMsg);
      break;
    default:
      break;
  }

  // Now enumerate the processes that processing this event might require access to...
  std::vector<struct santa::santad::process_tree::Pid> pids;
  pids.emplace_back(santa::santad::process_tree::PidFromAuditToken(esMsg->process->audit_token));
  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC:
    case ES_EVENT_TYPE_NOTIFY_EXEC:
      pids.emplace_back(santa::santad::process_tree::PidFromAuditToken(esMsg->event.exec.target->audit_token));
      break;
    case ES_EVENT_TYPE_NOTIFY_FORK:
      pids.emplace_back(santa::santad::process_tree::PidFromAuditToken(esMsg->event.fork.child->audit_token));
      break;
    default:
      break;
  }

  // ...and create the token for those.
  esMsg.SetProcessToken(santa::santad::process_tree::ProcessToken(_processTree, std::move(pids)));

  return _addedEvents[esMsg->event_type];
}

@end
