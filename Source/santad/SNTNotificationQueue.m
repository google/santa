/// Copyright 2016 Google Inc. All rights reserved.
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

#import "Source/santad/SNTNotificationQueue.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTXPCNotifierInterface.h"

static const int kMaximumNotifications = 10;

@interface SNTNotificationQueue ()
@property NSMutableArray *pendingNotifications;
@end

@implementation SNTNotificationQueue

- (instancetype)init {
  self = [super init];
  if (self) {
    _pendingNotifications = [NSMutableArray array];
  }
  return self;
}

- (void)addEvent:(SNTStoredEvent *)event customMessage:(NSString *)message {
  if (!event) return;
  if (self.pendingNotifications.count > kMaximumNotifications) {
    LOGI(@"Pending GUI notification count is over %d, dropping.", kMaximumNotifications);
    return;
  }

  NSDictionary *d;
  if (message) {
    d = @{@"event" : event,
          @"message" : message};
  } else {
    d = @{@"event" : event};
  }
  @synchronized(self.pendingNotifications) {
    [self.pendingNotifications addObject:d];
  }
  [self flushQueue];
}

- (void)flushQueue {
  id rop = [self.notifierConnection remoteObjectProxy];
  if (!rop) return;

  @synchronized(self.pendingNotifications) {
    NSMutableArray *postedNotifications = [NSMutableArray array];
    for (NSDictionary *d in self.pendingNotifications) {
      [rop postBlockNotification:d[@"event"] withCustomMessage:d[@"message"]];
      [postedNotifications addObject:d];
    }
    [self.pendingNotifications removeObjectsInArray:postedNotifications];
  }
}

- (void)setNotifierConnection:(MOLXPCConnection *)notifierConnection {
  _notifierConnection = notifierConnection;
  [self flushQueue];
}

@end
