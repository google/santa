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

#include <EndpointSecurity/EndpointSecurity.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#include "Source/common/String.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Metrics.h"

using santa::common::PrefixTree;
using santa::common::Unit;
using santa::santad::EventDisposition;
using santa::santad::event_providers::AuthResultCache;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::EnrichedMessage;
using santa::santad::event_providers::endpoint_security::Enricher;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::Logger;

es_file_t *GetTargetFileForPrefixTree(const es_message_t *msg) {
  switch (msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE: return msg->event.close.target;
    case ES_EVENT_TYPE_NOTIFY_LINK: return msg->event.link.source;
    case ES_EVENT_TYPE_NOTIFY_RENAME: return msg->event.rename.source;
    case ES_EVENT_TYPE_NOTIFY_UNLINK: return msg->event.unlink.target;
    default: return NULL;
  }
}

@interface SNTEndpointSecurityRecorder ()
@property SNTCompilerController *compilerController;
@property SNTConfigurator *configurator;
@end

@implementation SNTEndpointSecurityRecorder {
  std::shared_ptr<AuthResultCache> _authResultCache;
  std::shared_ptr<Enricher> _enricher;
  std::shared_ptr<Logger> _logger;
  std::shared_ptr<PrefixTree<Unit>> _prefixTree;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<santa::santad::Metrics>)metrics
                       logger:(std::shared_ptr<Logger>)logger
                     enricher:(std::shared_ptr<Enricher>)enricher
           compilerController:(SNTCompilerController *)compilerController
              authResultCache:(std::shared_ptr<AuthResultCache>)authResultCache
                   prefixTree:(std::shared_ptr<PrefixTree<Unit>>)prefixTree {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:std::move(metrics)
                    processor:santa::santad::Processor::kRecorder];
  if (self) {
    _enricher = enricher;
    _logger = logger;
    _compilerController = compilerController;
    _authResultCache = authResultCache;
    _prefixTree = prefixTree;
    _configurator = [SNTConfigurator configurator];

    [self establishClientOrDie];
  }
  return self;
}

- (NSString *)description {
  return @"Recorder";
}

- (void)handleMessage:(Message &&)esMsg
   recordEventMetrics:(void (^)(EventDisposition))recordEventMetrics {
  // Pre-enrichment processing
  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE: {
      BOOL shouldLogClose = esMsg->event.close.modified;

#if HAVE_MACOS_13
      if (@available(macOS 13.5, *)) {
        // As of macSO 13.0 we have a new field for if a file was mmaped with
        // write permissions on close events. However it did not work until
        // 13.5.
        //
        // If something was mmaped writable it was probably written to. Often
        // developer tools do this to avoid lots of write syscalls, e.g. go's
        // tool chain. We log this so the compiler controller can take that into
        // account.
        shouldLogClose |= esMsg->event.close.was_mapped_writable;
      }
#endif

      if (!shouldLogClose) {
        // Ignore unmodified files
        // Note: Do not record metrics in this case. These are not considered "drops"
        // because this is not a failure case. Ideally we would tell ES to not send
        // these events in the first place but no such mechanism currently exists.
        return;
      }

      self->_authResultCache->RemoveFromCache(esMsg->event.close.target);

      // Only log file changes that match the given regex
      NSString *targetPath = santa::common::StringToNSString(esMsg->event.close.target->path.data);
      if (![[self.configurator fileChangesRegex]
            numberOfMatchesInString:targetPath
                            options:0
                              range:NSMakeRange(0, targetPath.length)]) {
        // Note: Do not record metrics in this case. These are not considered "drops"
        // because this is not a failure case.
        // TODO(mlw): Consider changes to configuration that would allow muting paths
        // to filter on the kernel side rather than in user space.
        return;
      }

      break;
    }
    default: break;
  }

  [self.compilerController handleEvent:esMsg withLogger:self->_logger];

  if ((esMsg->event_type == ES_EVENT_TYPE_NOTIFY_FORK ||
       esMsg->event_type == ES_EVENT_TYPE_NOTIFY_EXIT) &&
      self.configurator.enableForkAndExitLogging == NO) {
    recordEventMetrics(EventDisposition::kDropped);
    return;
  }

  // Filter file op events matching the prefix tree.
  es_file_t *targetFile = GetTargetFileForPrefixTree(&(*esMsg));
  if (targetFile != NULL && self->_prefixTree->HasPrefix(targetFile->path.data)) {
    recordEventMetrics(EventDisposition::kDropped);
    return;
  }

  // Enrich the message inline with the ES handler block to capture enrichment
  // data as close to the source event as possible.
  std::unique_ptr<EnrichedMessage> enrichedMessage = _enricher->Enrich(std::move(esMsg));

  // Asynchronously log the message
  [self processEnrichedMessage:std::move(enrichedMessage)
                       handler:^(std::unique_ptr<EnrichedMessage> msg) {
                         self->_logger->Log(std::move(msg));
                         recordEventMetrics(EventDisposition::kProcessed);
                       }];
}

- (void)enable {
  [super subscribe:{
                     ES_EVENT_TYPE_NOTIFY_CLOSE,
                     ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
                     ES_EVENT_TYPE_NOTIFY_EXEC,
                     ES_EVENT_TYPE_NOTIFY_EXIT,
                     ES_EVENT_TYPE_NOTIFY_FORK,
                     ES_EVENT_TYPE_NOTIFY_LINK,
                     ES_EVENT_TYPE_NOTIFY_RENAME,
                     ES_EVENT_TYPE_NOTIFY_UNLINK,
                   }];
}

@end
