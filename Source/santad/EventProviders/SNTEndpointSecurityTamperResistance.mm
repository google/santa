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

#import "Source/santad/EventProviders/SNTEndpointSecurityTamperResistance.h"

#include <EndpointSecurity/ESTypes.h>
#include <string.h>

#import "Source/common/SNTLogging.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Metrics.h"

using santa::santad::EventDisposition;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::Logger;

static constexpr std::string_view kSantaKextIdentifier = "com.google.santa-driver";

@implementation SNTEndpointSecurityTamperResistance {
  std::shared_ptr<Logger> _logger;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<santa::santad::Metrics>)metrics
                       logger:(std::shared_ptr<Logger>)logger {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:std::move(metrics)
                    processor:santa::santad::Processor::kTamperResistance];
  if (self) {
    _logger = logger;

    [self establishClientOrDie];
  }
  return self;
}

- (void)handleMessage:(Message &&)esMsg
   recordEventMetrics:(void (^)(EventDisposition))recordEventMetrics {
  es_auth_result_t result = ES_AUTH_RESULT_ALLOW;
  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_AUTH_UNLINK: {
      if ([SNTEndpointSecurityTamperResistance
            isDatabasePath:esMsg->event.unlink.target->path.data]) {
        result = ES_AUTH_RESULT_DENY;
        LOGW(@"Preventing attempt to delete Santa databases!");
      }
      break;
    }

    case ES_EVENT_TYPE_AUTH_RENAME: {
      if ([SNTEndpointSecurityTamperResistance
            isDatabasePath:esMsg->event.rename.source->path.data]) {
        result = ES_AUTH_RESULT_DENY;
        LOGW(@"Preventing attempt to rename Santa databases!");
        break;
      }

      if (esMsg->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        if ([SNTEndpointSecurityTamperResistance
              isDatabasePath:esMsg->event.rename.destination.existing_file->path.data]) {
          result = ES_AUTH_RESULT_DENY;
          LOGW(@"Preventing attempt to overwrite Santa databases!");
          break;
        }
      }

      break;
    }

    case ES_EVENT_TYPE_AUTH_KEXTLOAD: {
      // TODO(mlw): Since we don't package the kext anymore, we should consider removing this.
      // TODO(mlw): Consider logging when kext loads are attempted.
      if (strcmp(esMsg->event.kextload.identifier.data, kSantaKextIdentifier.data()) == 0) {
        result = ES_AUTH_RESULT_DENY;
        LOGW(@"Preventing attempt to load Santa kext!");
      }
      break;
    }

    default:
      // Unexpected event type, this is a programming error
      [NSException raise:@"Invalid event type"
                  format:@"Invalid tamper resistance event type: %d", esMsg->event_type];
  }

  // Do not cache denied operations so that each tamper attempt is logged
  [self respondToMessage:esMsg withAuthResult:result cacheable:result == ES_AUTH_RESULT_ALLOW];

  // For this client, a processed event is one that was found to be violating anti-tamper policy
  recordEventMetrics(result == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                   : EventDisposition::kDropped);
}

- (void)enable {
  // TODO(mlw): For macOS 13, use new mute and invert APIs to limit the
  // messages sent for these events to the Santa-specific directories
  // checked in the `handleMessage:` method.

  [super subscribeAndClearCache:{
                                  ES_EVENT_TYPE_AUTH_KEXTLOAD,
                                  ES_EVENT_TYPE_AUTH_UNLINK,
                                  ES_EVENT_TYPE_AUTH_RENAME,
                                }];
}

@end
