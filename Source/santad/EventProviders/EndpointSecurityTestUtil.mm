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

#import "Source/santad/EventProviders/EndpointSecurityTestUtil.h"

CF_EXTERN_C_BEGIN
es_string_token_t MakeStringToken(const NSString *s) {
  return (es_string_token_t){
    .length = [s length],
    .data = [s UTF8String],
  };
}
CF_EXTERN_C_END

@implementation ESResponse
@end

@interface MockEndpointSecurity ()
@property NSMutableArray<ESCallback> *responseCallbacks;
@property NSObject *client;
@property es_handler_block_t handler;
@end

@implementation MockEndpointSecurity
- (instancetype)init {
  self = [super init];
  if (self) {
    _responseCallbacks = [NSMutableArray array];
    _subscribed = YES;
  }
  return self;
};

- (void)reset {
  @synchronized(self) {
    [self.responseCallbacks removeAllObjects];
    self.handler = nil;
    self.client = nil;
    self.subscribed = NO;
  }
};

- (void)newClient:(es_client_t *_Nullable *_Nonnull)client
          handler:(es_handler_block_t __strong)handler {
  // es_client_t is generally used as a pointer to an opaque struct (secretly a mach port).
  // We just want to set it to something nonnull for passing initialization checks. It shouldn't
  // ever be directly dereferenced.
  self.client = [[NSObject alloc] init];
  *client = (__bridge es_client_t *)self.client;
  self.handler = handler;
}

- (void)triggerHandler:(es_message_t *)msg {
  self.handler((__bridge es_client_t *)self.client, msg);
}

- (void)registerResponseCallback:(ESCallback)callback {
  @synchronized(self) {
    [self.responseCallbacks addObject:callback];
  }
}

- (es_respond_result_t)respond_auth_result:(const es_message_t *_Nonnull)msg
                                    result:(es_auth_result_t)result
                                     cache:(bool)cache {
  @synchronized(self) {
    ESResponse *response = [[ESResponse alloc] init];
    response.result = result;
    response.shouldCache = cache;
    for (void (^callback)(ESResponse *) in self.responseCallbacks) {
      callback(response);
    }
  }
  return ES_RESPOND_RESULT_SUCCESS;
};

+ (instancetype)mockEndpointSecurity {
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

API_AVAILABLE(macos(10.15))
API_UNAVAILABLE(ios, tvos, watchos) es_return_t es_delete_client(es_client_t *_Nullable client) {
  [[MockEndpointSecurity mockEndpointSecurity] reset];
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
  [MockEndpointSecurity mockEndpointSecurity].subscribed = YES;
  return ES_RETURN_SUCCESS;
}
API_AVAILABLE(macos(10.15))
API_UNAVAILABLE(ios, tvos, watchos)
es_return_t es_unsubscribe(es_client_t *_Nonnull client, const es_event_type_t *_Nonnull events,
                           uint32_t event_count) {
  [MockEndpointSecurity mockEndpointSecurity].subscribed = NO;

  return ES_RETURN_SUCCESS;
};
