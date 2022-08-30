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

using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::Logger;

static constexpr std::string_view kSantaKextIdentifier = "com.google.santa-driver";

@implementation SNTEndpointSecurityTamperResistance {
  std::shared_ptr<Logger> _logger;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                       logger:(std::shared_ptr<Logger>)logger {
  self = [super initWithESAPI:std::move(esApi)];
  if (self) {
    _logger = logger;

    [self establishClientOrDie];
  }
  return self;
}

- (void)handleMessage:(Message &&)esMsg {
  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_AUTH_UNLINK: {
      if ([SNTEndpointSecurityTamperResistance isDatabasePath:esMsg->event.unlink.target->path.data]) {
        // Do not cache so that each attempt to remove santa is logged
        [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_DENY cacheable:false];
        LOGW(@"Preventing attempt to delete Santa databases!");
      } else {
        [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_ALLOW cacheable:true];
      }

      return;
    }

    case ES_EVENT_TYPE_AUTH_RENAME: {
      if ([SNTEndpointSecurityTamperResistance isDatabasePath:esMsg->event.rename.source->path.data]) {
        // Do not cache so that each attempt to remove santa is logged
        [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_DENY cacheable:false];
        LOGW(@"Preventing attempt to rename Santa databases!");
        return;
      }

      if (esMsg->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        if ([SNTEndpointSecurityTamperResistance isDatabasePath:esMsg->event.rename.destination.existing_file->path.data]) {
          [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_DENY cacheable:false];
          LOGW(@"Preventing attempt to overwrite Santa databases!");
          return;
        }
      }

      // If we get to here, no more reasons to deny the event, so allow it
      [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_ALLOW cacheable:true];
      return;
    }

    case ES_EVENT_TYPE_AUTH_KEXTLOAD: {
      es_auth_result_t res = ES_AUTH_RESULT_ALLOW;
      if (strcmp(esMsg->event.kextload.identifier.data,
                  kSantaKextIdentifier.data()) == 0) {
        LOGW(@"Preventing attempt to load Santa kext!");
        res = ES_AUTH_RESULT_DENY;
      }
      [self respondToMessage:esMsg withAuthResult:res cacheable:true];
      return;
    }

    default:
      // Unexpected event type, this is a programming error
      [NSException raise:@"Invalid event type"
                  format:@"Invalid tamper resistance event type: %d",
                         esMsg->event_type];
  }
}

- (void)enable {
  // TODO(mlw): For macOS 13, use new mute and invert APIs to limit the
  // messages sent for these events to Santa-specific directories.

  [super subscribeAndClearCache:{
      ES_EVENT_TYPE_AUTH_KEXTLOAD,
      ES_EVENT_TYPE_AUTH_UNLINK,
      ES_EVENT_TYPE_AUTH_RENAME,
  }];
}

@end
