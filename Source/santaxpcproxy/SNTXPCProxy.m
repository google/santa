/// Copyright 2019 Google Inc. All rights reserved.
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

#import "SNTXPCProxy.h"

@interface SNTXPCProxy()
@property NSMutableDictionary<NSNumber *, NSXPCListenerEndpoint *> *registeredListeners;
@property dispatch_queue_t rwQueue;
@end

@implementation SNTXPCProxy

- (instancetype)init {
  self = [super init];
  if (self) {
    _registeredListeners = [NSMutableDictionary dictionary];
    _rwQueue = dispatch_queue_create(
        "com.google.santa.xpcproxy.listener_queue", DISPATCH_QUEUE_CONCURRENT);
  }
  return self;
}

- (void)registerListener:(NSXPCListenerEndpoint *)listener ofType:(SNTXPCType)type {
  dispatch_barrier_async(self.rwQueue, ^{
    self.registeredListeners[@(type)] = listener;
  });
}

- (void)removeListenerOfType:(SNTXPCType)type {
  dispatch_barrier_async(self.rwQueue, ^{
    self.registeredListeners[@(type)] = nil;
  });
}

- (void)lookupListenerOfType:(SNTXPCType)type
                       reply:(void (^)(NSXPCListenerEndpoint *listener))reply {
  switch(type) {
    case SNTXPCTypeBundleService:
      reply([self serviceWithName:@"com.google.santa.bundleservice"]);
    return;
    case SNTXPCTypeQurantineService:
      reply([self serviceWithName:@"com.google.santa.quarantineservice"]);
      return;
    case SNTXPCTypeSyncService:
      reply([self serviceWithName:@"com.google.santa.syncservice"]);
      return;
    default:
      break;
  }

  dispatch_sync(self.rwQueue, ^{
    reply(self.registeredListeners[@(type)]);
  });
}

// Services will spin up on demand.
// Multiple connections to the same service are multiplexed to a single instance of the service.
- (NSXPCListenerEndpoint *)serviceWithName:(NSString *)name {
  MOLXPCConnection *c = [[MOLXPCConnection alloc] initClientWithServiceName:name];
  c.remoteInterface = [SNTXPCProxyInterface proxyChildServiceInterface];
  [c resume];
  __block NSXPCListenerEndpoint *listener;
  id rop = [c synchronousRemoteObjectProxy];
  [rop anonymousListener:^(NSXPCListenerEndpoint *l) {
    listener = l;
  }];
  [c invalidate];
  return listener;
}

@end
