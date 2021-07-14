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

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>

es_string_token_t MakeStringToken(const NSString *s);

@interface ESResponse : NSObject
@property(nonatomic) es_auth_result_t result;
@property(nonatomic) bool shouldCache;
@end

typedef void (^ESCallback)(ESResponse *);

// Singleton wrapper around all of the kernel-level EndpointSecurity framework functions.
@interface MockEndpointSecurity : NSObject
- (void)reset;
- (void)registerResponseCallback:(ESCallback)callback;
- (void)triggerHandler:(es_message_t *)msg;

///  Retrieve an initialized singleton MockEndpointSecurity object
+ (instancetype)mockEndpointSecurity;
@end

API_UNAVAILABLE(ios, tvos, watchos)
es_message_t *_Nullable es_copy_message(const es_message_t *_Nonnull msg);

API_UNAVAILABLE(ios, tvos, watchos)
void es_free_message(es_message_t *_Nonnull msg);

API_AVAILABLE(macos(10.15))
API_UNAVAILABLE(ios, tvos, watchos)
es_new_client_result_t es_new_client(es_client_t *_Nullable *_Nonnull client,
                                     es_handler_block_t _Nonnull handler);

API_AVAILABLE(macos(10.15))
API_UNAVAILABLE(ios, tvos, watchos)
es_respond_result_t es_respond_auth_result(es_client_t *_Nonnull client,
                                           const es_message_t *_Nonnull message,
                                           es_auth_result_t result, bool cache);
