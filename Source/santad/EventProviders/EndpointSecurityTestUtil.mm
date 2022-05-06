/// Copyright 2021 Google Inc. All rights reserved.
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
#import <Foundation/Foundation.h>

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <stdlib.h>

#import "Source/santad/EventProviders/EndpointSecurityTestUtil.h"

CF_EXTERN_C_BEGIN
es_string_token_t MakeStringToken(const NSString *_Nonnull s) {
  return (es_string_token_t){
    .length = [s length],
    .data = [s UTF8String],
  };
}

es_file_t MakeESFile(const char *path) {
  es_file_t esFile = {};

  esFile.path.data = path;
  esFile.path.length = strlen(path);
  esFile.path_truncated = false;

  // Note: stat info is currently unused / not populated

  return esFile;
}

es_process_t MakeESProcess(es_file_t *esFile) {
  es_process_t esProc = {};
  esProc.executable = esFile;
  return esProc;
}

es_message_t MakeESMessage(es_event_type_t eventType, es_process_t *instigator,
                           struct timespec ts) {
  es_message_t esMsg = {};

  esMsg.time = ts;
  esMsg.event_type = eventType;
  esMsg.process = instigator;

  return esMsg;
}

CF_EXTERN_C_END

@implementation ESMessage
- (instancetype)init {
  return [self initWithBlock:nil];
}

- (instancetype)initWithBlock:(ESMessageBuilderBlock)block {
  NSParameterAssert(block);

  self = [super init];
  if (self) {
    _pid = arc4random();
    [self initBaseObjects];
    block(self);
    [self fillLinks];
  }
  return self;
}

- (void)initBaseObjects {
  self.executable = static_cast<es_file_t *>(calloc(1, sizeof(es_file_t)));
  self.process = static_cast<es_process_t *>(calloc(1, sizeof(es_process_t)));

  self.process->ppid = self.pid;
  self.process->original_ppid = self.pid;
  self.process->group_id = static_cast<pid_t>(arc4random());
  self.process->session_id = static_cast<pid_t>(arc4random());
  self.process->codesigning_flags =
    0x1 | 0x20000000;  // CS_VALID | CS_SIGNED -> See kern/cs_blobs.h
  self.process->is_platform_binary = false;
  self.process->is_es_client = false;

  self.message = static_cast<es_message_t *>(calloc(1, sizeof(es_message_t)));
  self.message->version = 4;
  self.message->mach_time = DISPATCH_TIME_NOW;
  self.message->deadline = DISPATCH_TIME_FOREVER;
  self.message->seq_num = 1;
}

- (void)fillLinks {
  if (self.binaryPath != nil) {
    self.executable->path = MakeStringToken(self.binaryPath);
  }

  if (self.process->executable == NULL) {
    self.process->executable = self.executable;
  }
  if (self.message->process == NULL) {
    self.message->process = self.process;
  }
}

- (void)dealloc {
  free(self.process);
  free(self.executable);
  free(self.message);
}
@end

@implementation ESResponse
@end

@interface MockESClient : NSObject
@property NSMutableArray *_Nonnull subscriptions;
@property es_handler_block_t handler;
@end

@implementation MockESClient

- (instancetype)init {
  self = [super init];
  if (self) {
    @synchronized(self) {
      _subscriptions = [NSMutableArray arrayWithCapacity:ES_EVENT_TYPE_LAST];
      for (size_t i = 0; i < ES_EVENT_TYPE_LAST; i++) {
        [self.subscriptions addObject:@NO];
      }
    }
  }
  return self;
};

- (void)resetSubscriptions {
  for (size_t i = 0; i < ES_EVENT_TYPE_LAST; i++) {
    _subscriptions[i] = @NO;
  }
}

- (void)triggerHandler:(es_message_t *_Nonnull)msg {
  self.handler((__bridge es_client_t *_Nullable)self, msg);
}

- (void)dealloc {
  @synchronized(self) {
    [self.subscriptions removeAllObjects];
  }
}

@end

@interface MockEndpointSecurity ()
@property NSMutableArray<MockESClient *> *clients;

// Array of collections of ESCallback blocks
// This should be of size ES_EVENT_TYPE_LAST, allowing for indexing by ES_EVENT_TYPE_xxx members.
@property NSMutableArray<NSMutableArray<ESCallback> *> *responseCallbacks;
@end

@implementation MockEndpointSecurity
- (instancetype)init {
  self = [super init];
  if (self) {
    @synchronized(self) {
      _clients = [NSMutableArray array];
      _responseCallbacks = [NSMutableArray arrayWithCapacity:ES_EVENT_TYPE_LAST];
      for (size_t i = 0; i < ES_EVENT_TYPE_LAST; i++) {
        [self.responseCallbacks addObject:[NSMutableArray array]];
      }
      [self reset];
    }
  }
  return self;
};

- (void)resetResponseCallbacks {
  for (NSMutableArray *callback in self.responseCallbacks) {
    if (callback != nil) {
      [callback removeAllObjects];
    }
  }
}

- (void)reset {
  @synchronized(self) {
    [self.clients removeAllObjects];
    [self resetResponseCallbacks];
  }
};

- (void)newClient:(es_client_t *_Nullable *_Nonnull)client
          handler:(es_handler_block_t __strong)handler {
  // es_client_t is generally used as a pointer to an opaque struct (secretly a mach port).
  // There is also a few nonnull initialization checks on it.
  MockESClient *mockClient = [[MockESClient alloc] init];
  *client = (__bridge es_client_t *)mockClient;
  mockClient.handler = handler;
  [self.clients addObject:mockClient];
}

- (BOOL)removeClient:(es_client_t *_Nonnull)client {
  MockESClient *clientToRemove = [self findClient:client];

  if (!clientToRemove) {
    NSLog(@"Attempted to remove unknown mock es client.");
    return NO;
  }

  [self.clients removeObject:clientToRemove];
  return YES;
}

- (void)triggerHandler:(es_message_t *_Nonnull)msg {
  for (MockESClient *client in self.clients) {
    if (client.subscriptions[msg->event_type]) {
      [client triggerHandler:msg];
    }
  }
}

- (void)registerResponseCallback:(es_event_type_t)t withCallback:(ESCallback _Nonnull)callback {
  @synchronized(self) {
    [self.responseCallbacks[t] addObject:callback];
  }
}

- (es_respond_result_t)respond_auth_result:(const es_message_t *_Nonnull)msg
                                    result:(es_auth_result_t)result
                                     cache:(bool)cache {
  @synchronized(self) {
    ESResponse *response = [[ESResponse alloc] init];
    response.result = result;
    response.shouldCache = cache;
    for (void (^callback)(ESResponse *) in self.responseCallbacks[msg->event_type]) {
      callback(response);
    }
  }
  return ES_RESPOND_RESULT_SUCCESS;
};

- (MockESClient *)findClient:(es_client_t *)client {
  for (MockESClient *c in self.clients) {
    // Since we're mocking out a C interface and using this exact pointer as our
    // client identifier, only check for pointer equality.
    if (client == (__bridge es_client_t *)c) {
      return c;
    }
  }
  return nil;
}

- (void)setSubscriptions:(const es_event_type_t *_Nonnull)events
             event_count:(uint32_t)event_count
                   value:(NSNumber *)value
                  client:(es_client_t *)client {
  @synchronized(self) {
    MockESClient *toUpdate = [self findClient:client];

    if (toUpdate == nil) {
      NSLog(@"setting subscription for unknown client");
      return;
    }

    for (size_t i = 0; i < event_count; i++) {
      toUpdate.subscriptions[events[i]] = value;
    }
  }
}

+ (instancetype _Nonnull)mockEndpointSecurity {
  static MockEndpointSecurity *sharedES;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedES = [[MockEndpointSecurity alloc] init];
  });
  return sharedES;
};
@end

API_UNAVAILABLE(ios, tvos, watchos)
es_message_t *_Nullable es_copy_message(const es_message_t *_Nonnull msg) {
  return (es_message_t *)msg;
};

API_UNAVAILABLE(ios, tvos, watchos)
void es_free_message(es_message_t *_Nonnull msg){};

API_AVAILABLE(macos(10.15))
API_UNAVAILABLE(ios, tvos, watchos)
es_new_client_result_t es_new_client(es_client_t *_Nullable *_Nonnull client,
                                     es_handler_block_t _Nonnull handler) {
  [[MockEndpointSecurity mockEndpointSecurity] newClient:client handler:handler];
  return ES_NEW_CLIENT_RESULT_SUCCESS;
};

#if defined(MAC_OS_VERSION_12_0) && MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_VERSION_12_0
API_AVAILABLE(macos(12.0))
API_UNAVAILABLE(ios, tvos, watchos)
es_return_t es_muted_paths_events(es_client_t *_Nonnull client,
                                  es_muted_paths_t *_Nonnull *_Nullable muted_paths) {
  es_muted_paths_t *tmp = (es_muted_paths_t *)malloc(sizeof(es_muted_paths_t));

  tmp->count = 0;
  *muted_paths = (es_muted_paths_t *_Nullable)tmp;

  return ES_RETURN_SUCCESS;
};

API_AVAILABLE(macos(12.0))
API_UNAVAILABLE(ios, tvos, watchos)
void es_release_muted_paths(es_muted_paths_t *_Nonnull muted_paths) {
  free(muted_paths);
}
#endif

API_AVAILABLE(macos(10.15))
API_UNAVAILABLE(ios, tvos, watchos) es_return_t es_delete_client(es_client_t *_Nullable client) {
  if (![[MockEndpointSecurity mockEndpointSecurity] removeClient:client]) {
    return ES_RETURN_ERROR;
  }
  return ES_RETURN_SUCCESS;
};

API_AVAILABLE(macos(10.15))
API_UNAVAILABLE(ios, tvos, watchos)
es_respond_result_t es_respond_auth_result(es_client_t *_Nonnull client,
                                           const es_message_t *_Nonnull message,
                                           es_auth_result_t result, bool cache) {
  return [[MockEndpointSecurity mockEndpointSecurity] respond_auth_result:message
                                                                   result:result
                                                                    cache:cache];
};

API_AVAILABLE(macos(10.15))
API_UNAVAILABLE(ios, tvos, watchos)
es_return_t es_subscribe(es_client_t *_Nonnull client, const es_event_type_t *_Nonnull events,
                         uint32_t event_count) {
  [[MockEndpointSecurity mockEndpointSecurity] setSubscriptions:events
                                                    event_count:event_count
                                                          value:@YES
                                                         client:client];
  return ES_RETURN_SUCCESS;
}
API_AVAILABLE(macos(10.15))
API_UNAVAILABLE(ios, tvos, watchos)
es_return_t es_unsubscribe(es_client_t *_Nonnull client, const es_event_type_t *_Nonnull events,
                           uint32_t event_count) {
  [[MockEndpointSecurity mockEndpointSecurity] setSubscriptions:events
                                                    event_count:event_count
                                                          value:@NO
                                                         client:client];

  return ES_RETURN_SUCCESS;
};
