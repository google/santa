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

- (NSXPCListenerEndpoint *)lookupListenerOfType:(SNTXPCType)type {
  switch(type) {
    case SNTXPCTypeBundleService:
      return [self serviceWithName:@"com.google.santa.bundleservice"];
    case SNTXPCTypeQurantineService:
      return [self serviceWithName:@"com.google.santa.quarantineservice"];
    case SNTXPCTypeSyncService:
      return [self serviceWithName:@"com.google.santa.syncservice"];
    default:
      break;
  }

  __block NSXPCListenerEndpoint *listener;
  dispatch_sync(self.rwQueue, ^{
    listener = self.registeredListeners[@(type)];
  });
  return listener;
}

- (NSXPCListenerEndpoint *)serviceWithName:(NSString *)name {
  NSXPCConnection *c = [[NSXPCConnection alloc] initWithServiceName:name];
  return c.endpoint;
}

@end
