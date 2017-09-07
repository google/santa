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

#import "SNTSyncdQueue.h"

#import "SNTLogging.h"
#import "SNTStoredEvent.h"
#import "SNTXPCConnection.h"
#import "SNTXPCSyncdInterface.h"

@interface SNTSyncdQueue ()
@property NSCache<NSString *, NSDate *> *uploadBackoff;
@property dispatch_queue_t syncdQueue;
@property dispatch_semaphore_t sema;
@end

@implementation SNTSyncdQueue

- (instancetype)init {
  self = [super init];
  if (self) {
    _uploadBackoff = [[NSCache alloc] init];
    _uploadBackoff.countLimit = 128;
    _syncdQueue = dispatch_queue_create("com.google.syncd_queue", DISPATCH_QUEUE_SERIAL);
    _sema = dispatch_semaphore_create(0);
  }
  return self;
}

- (void)addEvents:(NSArray<SNTStoredEvent *> *)events isFromBundle:(BOOL)isFromBundle {
  if (!events.count) return;
  SNTStoredEvent *first = events.firstObject;
  NSString *hash = isFromBundle ? first.fileBundleHash : first.fileSHA256;
  if (![self backoffForPrimaryHash:hash]) return;
  [self dispatchBlockOnSyncdQueue:^{
    [self.syncdConnection.remoteObjectProxy postEventsToSyncServer:events
                                                      isFromBundle:isFromBundle];
  }];
}

- (void)addBundleEvent:(SNTStoredEvent *)event reply:(void (^)(BOOL))reply {
  if (![self backoffForPrimaryHash:event.fileBundleHash]) return;
  [self dispatchBlockOnSyncdQueue:^{
    [self.syncdConnection.remoteObjectProxy postBundleEventToSyncServer:event
                                                                  reply:^(BOOL needRelatedEvents) {
      // Remove the backoff entry for the inital block event. The same event will be included in the
      // related events synced using addEvents:isFromBundle:.
      if (needRelatedEvents) [self.uploadBackoff removeObjectForKey:event.fileBundleHash];
      reply(needRelatedEvents);
    }];
  }];
}

- (void)startSyncingEvents {
  dispatch_semaphore_signal(self.sema);
}

- (void)stopSyncingEvents {
  self.sema = dispatch_semaphore_create(0);
}

// Hold events for a few seconds to allow santad and santactl to establish connections.
// If the connections are not established in time drop the event from the queue.
// They will be uploaded during a full sync.
- (void)dispatchBlockOnSyncdQueue:(void (^)())block {
  dispatch_async(self.syncdQueue, ^{
    if (!dispatch_semaphore_wait(self.sema, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC))) {
      if (block) block();
      dispatch_semaphore_signal(self.sema);
    } else {
      LOGD(@"Dropping block %@ from com.google.syncd_queue", block);
    }
  });
}

// The event upload is skipped if an event has been initiated for it in the last 10 minutes.
// The passed-in hash is fileBundleHash for a bundle event, or fileSHA256 for a normal event.
- (BOOL)backoffForPrimaryHash:(NSString *)hash {
  NSDate *backoff = [self.uploadBackoff objectForKey:hash];
  NSDate *now = [NSDate date];
  if (([now timeIntervalSince1970] - [backoff timeIntervalSince1970]) < 600) return NO;
  [self.uploadBackoff setObject:now forKey:hash];
  return YES;
}

@end
