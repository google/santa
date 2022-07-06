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
  self = [super initWithESAPI:esApi];
  if (self) {
    _enricher = enricher;
    _logger = logger;
    _compilerController = compilerController;
    _authResultCache = authResultCache;
    _prefixTree = prefixTree;

    [self establishClient];
  }
  return self;
}

- (void)establishClient {
  [super establishClientOrDie:^(es_client_t *c, Message&& esMsg){
    // Pre-enrichment processing
    es_file_t *targetFile = NULL;

    switch(esMsg->event_type) {
      case ES_EVENT_TYPE_NOTIFY_CLOSE:
        if (esMsg->event.close.modified == false) {
          // Ignore unmodified files
          return;
        }

        self->_authResultCache->RemoveFromCache(esMsg->event.close.target);

        targetFile = esMsg->event.close.target;
        break;
      case ES_EVENT_TYPE_NOTIFY_LINK:
        targetFile = esMsg->event.link.source;
        break;
      case ES_EVENT_TYPE_NOTIFY_RENAME:
        targetFile = esMsg->event.rename.source;
        break;
      case ES_EVENT_TYPE_NOTIFY_UNLINK:
        targetFile = esMsg->event.unlink.target;
        break;
      default:
        targetFile = NULL;
        break;
    }

    [self.compilerController handleEvent:esMsg withLogger:self->_logger];

    // Filter file op events matching the prefix tree.
    if (targetFile != NULL &&
        self->_prefixTree->HasPrefix(targetFile->path.data)) {
      return;
    }

    // Enrich the message
    std::unique_ptr<EnrichedMessage> enrichedMsg = _enricher->Enrich(std::move(esMsg));

    // TODO: dispatch before logging
    self->_logger->Log(std::move(enrichedMsg));
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
