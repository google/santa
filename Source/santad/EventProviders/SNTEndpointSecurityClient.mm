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

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach_time.h>
#include <stdlib.h>
#include <sys/qos.h>

#include <algorithm>
#include <set>
#include <string>
#include <string_view>

#include "Source/common/BranchPrediction.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#include "Source/common/SystemResources.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Client.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Metrics.h"

using santa::WatchItemPathType;
using santa::santad::EventDisposition;
using santa::santad::Metrics;
using santa::santad::Processor;
using santa::santad::event_providers::endpoint_security::Client;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::EnrichedMessage;
using santa::santad::event_providers::endpoint_security::Message;

constexpr std::string_view kProtectedFiles[] = {"/private/var/db/santa/rules.db",
                                                "/private/var/db/santa/events.db"};

@interface SNTEndpointSecurityClient ()
@property(nonatomic) double defaultBudget;
@property(nonatomic) int64_t minAllowedHeadroom;
@property(nonatomic) int64_t maxAllowedHeadroom;
@property SNTConfigurator *configurator;
@end

@implementation SNTEndpointSecurityClient {
  std::shared_ptr<EndpointSecurityAPI> _esApi;
  std::shared_ptr<Metrics> _metrics;
  Client _esClient;
  dispatch_queue_t _authQueue;
  dispatch_queue_t _notifyQueue;
  Processor _processor;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<Metrics>)metrics
                    processor:(Processor)processor {
  self = [super init];
  if (self) {
    _esApi = std::move(esApi);
    _metrics = std::move(metrics);
    _configurator = [SNTConfigurator configurator];
    _processor = processor;

    // Default event processing budget is 80% of the deadline time
    _defaultBudget = 0.8;

    // For events with small deadlines, clamp processing budget to 1s headroom
    _minAllowedHeadroom = 1 * NSEC_PER_SEC;

    // For events with large deadlines, clamp processing budget to 5s headroom
    _maxAllowedHeadroom = 5 * NSEC_PER_SEC;

    _authQueue = dispatch_queue_create(
      "com.google.santa.daemon.auth_queue",
      dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_CONCURRENT_WITH_AUTORELEASE_POOL,
                                              QOS_CLASS_USER_INTERACTIVE, 0));

    _notifyQueue = dispatch_queue_create(
      "com.google.santa.daemon.notify_queue",
      dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_CONCURRENT_WITH_AUTORELEASE_POOL,
                                              QOS_CLASS_UTILITY, 0));
  }
  return self;
}

- (NSString *)errorMessageForNewClientResult:(es_new_client_result_t)result {
  switch (result) {
    case ES_NEW_CLIENT_RESULT_SUCCESS: return nil;
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: return @"Full-disk access not granted";
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: return @"Not entitled";
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return @"Not running as root";
    case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: return @"Invalid argument";
    case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: return @"Internal error";
    case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return @"Too many simultaneous clients";
    default: return @"Unknown error";
  }
}

- (void)handleMessage:(Message &&)esMsg
   recordEventMetrics:(void (^)(EventDisposition disposition))recordEventMetrics {
  // This method should only be used by classes derived
  // from SNTEndpointSecurityClient.
  [self doesNotRecognizeSelector:_cmd];
}

- (BOOL)shouldHandleMessage:(const Message &)esMsg {
  if (esMsg->process->is_es_client && [self.configurator ignoreOtherEndpointSecurityClients]) {
    if (esMsg->action_type == ES_ACTION_TYPE_AUTH) {
      [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_ALLOW cacheable:true];
    }
    return NO;
  }

  return YES;
}

- (bool)handleContextMessage:(Message &)esMsg {
  return false;
}

- (void)establishClientOrDie {
  if (self->_esClient.IsConnected()) {
    // This is a programming error
    LOGE(@"Client already established. Aborting.");
    [NSException raise:@"Client already established" format:@"IsConnected already true"];
  }

  self->_esClient = self->_esApi->NewClient(^(es_client_t *c, Message esMsg) {
    int64_t processingStart = clock_gettime_nsec_np(CLOCK_MONOTONIC);

    // Update event stats BEFORE calling into the processor class to ensure
    // sequence numbers are processed in order.
    self->_metrics->UpdateEventStats(self->_processor, esMsg.operator->());

    if ([self handleContextMessage:esMsg]) {
      int64_t processingEnd = clock_gettime_nsec_np(CLOCK_MONOTONIC);
      self->_metrics->SetEventMetrics(self->_processor, EventDisposition::kProcessed,
                                      processingEnd - processingStart, esMsg);
      return;
    }

    if ([self shouldHandleMessage:esMsg]) {
      [self handleMessage:std::move(esMsg)
        recordEventMetrics:^(EventDisposition disposition) {
          int64_t processingEnd = clock_gettime_nsec_np(CLOCK_MONOTONIC);
          self->_metrics->SetEventMetrics(self->_processor, disposition,
                                          processingEnd - processingStart, esMsg);
        }];
    } else {
      int64_t processingEnd = clock_gettime_nsec_np(CLOCK_MONOTONIC);
      self->_metrics->SetEventMetrics(self->_processor, EventDisposition::kDropped,
                                      processingEnd - processingStart, esMsg);
    }
  });

  if (!self->_esClient.IsConnected()) {
    NSString *errMsg = [self errorMessageForNewClientResult:_esClient.NewClientResult()];
    LOGE(@"Unable to create EndpointSecurity client: %@", errMsg);
    [NSException raise:@"Failed to create ES client" format:@"%@", errMsg];
  } else {
    LOGI(@"Connected to EndpointSecurity (%@)", self);
  }

  if (![self muteSelf]) {
    [NSException raise:@"ES Mute Failure" format:@"Failed to mute self"];
  }
}

+ (bool)populateAuditTokenSelf:(audit_token_t *)tok {
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)tok, &count) != KERN_SUCCESS) {
    LOGE(@"Failed to fetch this client's audit token.");
    return false;
  }

  return true;
}

- (bool)muteSelf {
  audit_token_t myAuditToken;
  if (![SNTEndpointSecurityClient populateAuditTokenSelf:&myAuditToken]) {
    return false;
  }

  if (!self->_esApi->MuteProcess(self->_esClient, &myAuditToken)) {
    LOGE(@"Failed to mute this client's process.");
    return false;
  }

  return true;
}

- (bool)clearCache {
  return _esApi->ClearCache(self->_esClient);
}

- (bool)subscribe:(const std::set<es_event_type_t> &)events {
  return _esApi->Subscribe(_esClient, events);
}

- (bool)subscribeAndClearCache:(const std::set<es_event_type_t> &)events {
  return [self subscribe:events] && [self clearCache];
}

- (bool)unsubscribeAll {
  return _esApi->UnsubscribeAll(_esClient);
}

- (bool)unmuteAllTargetPaths {
  return _esApi->UnmuteAllTargetPaths(_esClient);
}

- (bool)enableTargetPathWatching {
  [self unmuteAllTargetPaths];
  return _esApi->InvertTargetPathMuting(_esClient);
}

- (bool)muteTargetPaths:(const std::vector<std::pair<std::string, WatchItemPathType>> &)paths {
  bool result = true;
  for (const auto &pathAndTypePair : paths) {
    result =
      _esApi->MuteTargetPath(_esClient, pathAndTypePair.first, pathAndTypePair.second) && result;
  }
  return result;
}

- (bool)unmuteTargetPaths:(const std::vector<std::pair<std::string, WatchItemPathType>> &)paths {
  bool result = true;
  for (const auto &pathAndTypePair : paths) {
    result =
      _esApi->UnmuteTargetPath(_esClient, pathAndTypePair.first, pathAndTypePair.second) && result;
  }
  return result;
}

- (bool)respondToMessage:(const Message &)msg
          withAuthResult:(es_auth_result_t)result
               cacheable:(bool)cacheable {
  if (msg->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
    return _esApi->RespondFlagsResult(
      // For now, Santa is only concerned about alllowing all access or no
      // access, hence the flags being translated here to all or nothing based
      // on the auth result. In the future it might be beneficial to expand the
      // scope of Santa to enforce things like read-only access.
      _esClient, msg, (result == ES_AUTH_RESULT_ALLOW) ? 0xffffffff : 0x0, cacheable);
  } else {
    return _esApi->RespondAuthResult(_esClient, msg, result, cacheable);
  }
}

- (void)processEnrichedMessage:(std::unique_ptr<EnrichedMessage>)msg
                       handler:(void (^)(std::unique_ptr<EnrichedMessage>))messageHandler {
  __block std::unique_ptr<EnrichedMessage> msgTmp = std::move(msg);
  dispatch_async(_notifyQueue, ^{
    messageHandler(std::move(msgTmp));
  });
}

- (void)asynchronouslyProcess:(Message)msg handler:(void (^)(Message &&))messageHandler {
  __block Message msgTmp = std::move(msg);
  dispatch_async(_notifyQueue, ^{
    messageHandler(std::move(msgTmp));
  });
}

- (int64_t)computeBudgetForDeadline:(uint64_t)deadline currentTime:(uint64_t)currentTime {
  // First get how much time we have left
  int64_t nanosUntilDeadline = (int64_t)MachTimeToNanos(deadline - currentTime);

  // Compute the desired budget
  int64_t budget = nanosUntilDeadline * self.defaultBudget;

  // See how much headroom is left
  int64_t headroom = nanosUntilDeadline - budget;

  // Clamp headroom to maximize budget but ensure it's not so large as to not leave
  // enough time to respond in an emergency.
  headroom = std::clamp(headroom, self.minAllowedHeadroom, self.maxAllowedHeadroom);

  // Return the processing budget given the allotted headroom
  return nanosUntilDeadline - headroom;
}

- (void)processMessage:(Message &&)msg handler:(void (^)(const Message &))messageHandler {
  if (unlikely(msg->action_type != ES_ACTION_TYPE_AUTH)) {
    // This is a programming error
    LOGE(@"Attempting to process non-AUTH message");
    [NSException raise:@"Attempt to process non-auth message"
                format:@"Unexpected event type received: %d", msg->event_type];
  }

  dispatch_semaphore_t processingSema = dispatch_semaphore_create(0);
  // Add 1 to the processing semaphore. We're not creating it with a starting
  // value of 1 because that requires that the semaphore is not deallocated
  // until its value matches the starting value, which we don't need.
  dispatch_semaphore_signal(processingSema);
  dispatch_semaphore_t deadlineExpiredSema = dispatch_semaphore_create(0);

  int64_t processingBudget = [self computeBudgetForDeadline:msg->deadline
                                                currentTime:mach_absolute_time()];

  // Workaround for compiler bug that doesn't properly close over variables
  __block Message processMsg = msg;
  __block Message deadlineMsg = msg;

  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, processingBudget), self->_authQueue, ^(void) {
    if (dispatch_semaphore_wait(processingSema, DISPATCH_TIME_NOW) != 0) {
      // Handler has already responded, nothing to do.
      return;
    }

    es_auth_result_t authResult;
    if (self.configurator.failClosed) {
      authResult = ES_AUTH_RESULT_DENY;
    } else {
      authResult = ES_AUTH_RESULT_ALLOW;
    }

    bool res = [self respondToMessage:deadlineMsg withAuthResult:authResult cacheable:false];

    LOGE(@"SNTEndpointSecurityClient: deadline reached: pid=%d, event type: %d, result: %@, ret=%d",
         audit_token_to_pid(deadlineMsg->process->audit_token), deadlineMsg->event_type,
         (authResult == ES_AUTH_RESULT_DENY ? @"denied" : @"allowed"), res);
    dispatch_semaphore_signal(deadlineExpiredSema);
  });

  dispatch_async(self->_authQueue, ^{
    messageHandler(processMsg);
    if (dispatch_semaphore_wait(processingSema, DISPATCH_TIME_NOW) != 0) {
      // Deadline expired, wait for deadline block to finish.
      dispatch_semaphore_wait(deadlineExpiredSema, DISPATCH_TIME_FOREVER);
    }
  });
}

+ (std::set<std::string>)getProtectedPaths {
  std::set<std::string> protectedPathsCopy;

  for (size_t i = 0; i < sizeof(kProtectedFiles) / sizeof(kProtectedFiles[0]); i++) {
    protectedPathsCopy.insert(std::string(kProtectedFiles[i]));
  }

  return protectedPathsCopy;
}

+ (bool)isProtectedPath:(const std::string_view)path {
  // TODO(mlw): These values should come from `SNTDatabaseController`. But right
  // now they live as NSStrings. We should make them `std::string_view` types
  // in order to use them here efficiently, but will need to make the
  // `SNTDatabaseController` an ObjC++ file.
  for (size_t i = 0; i < sizeof(kProtectedFiles) / sizeof(kProtectedFiles[0]); i++) {
    if (path == kProtectedFiles[i]) {
      return true;
    }
  }

  return false;
}

@end
