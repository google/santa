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

#import "Source/santad/EventProviders/SNTEndpointSecurityRecorder.h"

#include <EndpointSecurity/ESTypes.h>

#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#import "Source/common/SNTLogging.h"

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::logs::endpoint_security::Logger;
using santa::santad::event_providers::endpoint_security::Enricher;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::event_providers::endpoint_security::EnrichedMessage;
using santa::santad::event_providers::AuthResultCache;

static inline es_file_t* GetTargetFileForPrefixTree(const es_message_t* msg) {
  switch(msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
      return msg->event.close.target;
    case ES_EVENT_TYPE_NOTIFY_LINK:
      return msg->event.link.source;
    case ES_EVENT_TYPE_NOTIFY_RENAME:
      return msg->event.rename.source;
    case ES_EVENT_TYPE_NOTIFY_UNLINK:
      return msg->event.unlink.target;
    default:
      return NULL;
  }
}

@interface SNTEndpointSecurityRecorder()
@property SNTCompilerController* compilerController;
@end

@implementation SNTEndpointSecurityRecorder {
  std::shared_ptr<AuthResultCache> _authResultCache;
  std::shared_ptr<Enricher> _enricher;
  std::shared_ptr<Logger> _logger;
  std::shared_ptr<SNTPrefixTree> _prefixTree;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                       logger:(std::shared_ptr<Logger>)logger
                     enricher:(std::shared_ptr<Enricher>)enricher
           compilerController:(SNTCompilerController*)compilerController
              authResultCache:(std::shared_ptr<AuthResultCache>)authResultCache
                   prefixTree:(std::shared_ptr<SNTPrefixTree>)prefixTree {
  self = [super initWithESAPI:std::move(esApi)];
  if (self) {
    _enricher = enricher;
    _logger = logger;
    _compilerController = compilerController;
    _authResultCache = authResultCache;
    _prefixTree = prefixTree;

    [self establishClientOrDie];
  }
  return self;
}

- (void)handleMessage:(Message &&)esMsg {
  // Pre-enrichment processing
  switch(esMsg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
      if (esMsg->event.close.modified == false) {
        // Ignore unmodified files
        return;
      }

      self->_authResultCache->RemoveFromCache(esMsg->event.close.target);
      break;
    default:
      break;
  }

  [self.compilerController handleEvent:esMsg withLogger:self->_logger];

  // Filter file op events matching the prefix tree.
  es_file_t *targetFile = GetTargetFileForPrefixTree(&(*esMsg));
  if (targetFile != NULL &&
      self->_prefixTree->HasPrefix(targetFile->path.data)) {
    return;
  }

  // Enrich the message inline with the ES handler block to capture enrichment
  // data as close to the source event as possible.
  std::shared_ptr<EnrichedMessage> sharedEnrichedMessage = _enricher->Enrich(std::move(esMsg));

  // Asynchronously log the message
  [self processEnrichedMessage:std::move(sharedEnrichedMessage) handler:^(std::shared_ptr<EnrichedMessage> msg){
    self->_logger->Log(std::move(msg));
  }];
}

- (void)enable {
  [super subscribe:{
      ES_EVENT_TYPE_NOTIFY_CLOSE,
      ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
      ES_EVENT_TYPE_NOTIFY_EXEC,
      ES_EVENT_TYPE_NOTIFY_FORK,
      ES_EVENT_TYPE_NOTIFY_EXIT,
      ES_EVENT_TYPE_NOTIFY_LINK,
      ES_EVENT_TYPE_NOTIFY_RENAME,
      ES_EVENT_TYPE_NOTIFY_UNLINK,
  }];
}

@end
