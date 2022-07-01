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

#import "Source/santad/EventProviders/SNTEndpointSecurityClient.h"
#include <bsm/libbsm.h>

#include <dispatch/dispatch.h>
#include <mach/mach_time.h>
#include <stdlib.h>

#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"

#import "Source/common/SNTLogging.h"

using santa::santad::event_providers::endpoint_security::Client;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Message;

@implementation SNTEndpointSecurityClient {
  std::shared_ptr<EndpointSecurityAPI> _esApi;
  Client _esClient;
  mach_timebase_info_data_t _timebase;
  dispatch_queue_t _authQueue;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi {
  self = [super init];
  if (self) {
    _esApi = esApi;

    if (mach_timebase_info(&_timebase) != KERN_SUCCESS) {
      LOGE(@"Failed to get mach timebase info");
      // Assumed to be transitory failure. Let the daemon restart.
      exit(EXIT_FAILURE);
    }

    _authQueue = dispatch_queue_create(
        "auth_queue",
        DISPATCH_QUEUE_CONCURRENT_WITH_AUTORELEASE_POOL);

  }
  return self;
}

- (void)establishClientOrDie:(void(^)(es_client_t *c, Message&& esMsg))messageHandler {
  if (self->_esClient.IsConnected()) {
    // This is a programming error
    LOGE(@"Client already established. Aborting.");
    exit(EXIT_FAILURE);
  }

  self->_esClient = self->_esApi->NewClient(^(es_client_t *c, Message esMsg) {
    messageHandler(c, std::move(esMsg));
  });

  if (!self->_esClient.IsConnected()) {
    switch(_esClient.NewClientResult()) {
      case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
        LOGE(@"Unable to create EndpointSecurity client, not full-disk access permitted");
      case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
        LOGE(@"Unable to create EndpointSecurity client, not entitled");
        break;
      case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
        LOGE(@"Unable to create EndpointSecurity client, not running as root");
        break;
      case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
        LOGE(@"Unable to create EndpointSecurity client, invalid argument");
        break;
      case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
        LOGE(@"Unable to create EndpointSecurity client, internal error");
        break;
      case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
        LOGE(@"Unable to create EndpointSecurity client, too many simultaneous clients");
        break;
      default:
        LOGE(@"Unable to create EndpointSecurity client, unknown error");
    }
    exit(EXIT_FAILURE);
  } else {
    LOGI(@"Connected to EndpointSecurity");
  }

  if (![self muteSelf]) {
    exit(EXIT_FAILURE);
  }
}

- (bool)muteSelf {
  audit_token_t myAuditToken;
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&myAuditToken, &count) ==
        KERN_SUCCESS) {
    if (self->_esApi->MuteProcess(self->_esClient, &myAuditToken)) {
      return true;
    } else {
      LOGE(@"Failed to mute this client's process.");
    }
  } else {
    LOGE(@"Failed to fetch this client's audit token.");
  }

  return false;
}

- (bool)clearCache {
  return _esApi->ClearCache(self->_esClient);
}

- (bool)subscribe:(std::set<es_event_type_t>)events {
  return _esApi->Subscribe(_esClient, events);
}

- (bool)respondToMessage:(const Message &)msg
          withAuthResult:(es_auth_result_t)result
               cacheable:(bool)cacheable {
  return _esApi->RespondAuthResult(_esClient, msg, result, cacheable);
}

- (void)processMessage:(Message&&)msg handler:(void(^)(const Message&))messageHandler {
  dispatch_semaphore_t processingSema = dispatch_semaphore_create(0);
  // Add 1 to the processing semaphore. We're not creating it with a starting
  // value of 1 because that requires that the semaphore is not deallocated
  // until its value matches the starting value, which we don't need.
  dispatch_semaphore_signal(processingSema);
  dispatch_semaphore_t deadlineExpiredSema = dispatch_semaphore_create(0);

  uint64_t timeout = NSEC_PER_SEC * -5;

  uint64_t deadlineMachTime = msg->deadline - mach_absolute_time();
  uint64_t deadlineNano = deadlineMachTime * _timebase.numer / _timebase.denom;

  if (deadlineNano <= timeout) {
    // TODO???
    // Note: This currently will result in the event being immediately denied
  }

  // Workaround for compiler bug that doesn't properly close over variables
  __block auto processMsg = msg;
  __block auto deadlineMsg = msg;

  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, deadlineNano - timeout), self->_authQueue, ^(void) {
    if (dispatch_semaphore_wait(processingSema, DISPATCH_TIME_NOW) != 0) {
      // Handler has already responded, nothing to do.
      return;
    }

    bool res = [self respondToMessage:deadlineMsg
                       withAuthResult:ES_AUTH_RESULT_DENY
                            cacheable:false];

    LOGE(@"SNTEndpointSecurityClient: deadline reached: deny pid=%d, event type: %d ret=%d",
         audit_token_to_pid(deadlineMsg->process->audit_token),
         deadlineMsg->event_type,
         res);
    dispatch_semaphore_signal(deadlineExpiredSema);
  });

  dispatch_async(self->_authQueue, ^{
    messageHandler(deadlineMsg);
    if (dispatch_semaphore_wait(processingSema, DISPATCH_TIME_NOW) != 0) {
      // Deadline expired, wait for deadline block to finish.
      dispatch_semaphore_wait(deadlineExpiredSema, DISPATCH_TIME_FOREVER);
    }
  });
}

- (bool)isDatabasePath:(const std::string_view)path {
  return (path == "/private/var/db/santa/rules.db" ||
          path == "/private/var/db/santa/events.db");
}

@end
