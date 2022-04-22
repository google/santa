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
///    limitations under the License

#import "Source/santasyncservice/SNTSyncBroadcaster.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTXPCSyncServiceInterface.h"

@interface SNTSyncBroadcaster ()
@property NSMutableArray *logListeners;
@property dispatch_queue_t broadcastQueue;
@end

@implementation SNTSyncBroadcaster

- (instancetype)init {
  self = [super init];
  if (self) {
    _logListeners = [NSMutableArray array];
    _broadcastQueue =
      dispatch_queue_create("com.google.santa.syncservice.broadcast", DISPATCH_QUEUE_SERIAL);
  }
  return self;
}

+ (instancetype)broadcaster {
  static SNTSyncBroadcaster *sharedBroadcaster;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedBroadcaster = [[SNTSyncBroadcaster alloc] init];
  });
  return sharedBroadcaster;
}

- (void)addLogListener:(MOLXPCConnection *)logListener {
  dispatch_async(self.broadcastQueue, ^() {
    [self.logListeners addObject:logListener];
  });
}

- (void)removeLogListener:(MOLXPCConnection *)logListener {
  dispatch_async(self.broadcastQueue, ^() {
    [self.logListeners removeObject:logListener];
  });
}

- (void)broadcastToLogListeners:(NSString *)log {
  dispatch_async(self.broadcastQueue, ^() {
    for (MOLXPCConnection *ll in self.logListeners) {
      [[ll remoteObjectProxy] didReceiveLog:log];
    }
  });
}

- (void)barrier {
  dispatch_sync(self.broadcastQueue, ^() {
    return;
  });
}

@end
