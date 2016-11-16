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

- (void)addEvent:(SNTStoredEvent *)event {
  // The event upload is skipped if an event upload has been initiated for it in the
  // last 10 minutes.
  NSDate *backoff = [self.uploadBackoff objectForKey:event.fileSHA256];
  NSDate *now = [NSDate date];
  if (([now timeIntervalSince1970] - [backoff timeIntervalSince1970]) < 600) return;
  [self.uploadBackoff setObject:now forKey:event.fileSHA256];
  
  // Hold events for a few seconds to allow santad and santactl to establish connections.
  // If the connections are not established in time drop the event from the queue.
  // They will be uploaded during a full sync.
  dispatch_async(self.syncdQueue, ^{
    if (!dispatch_semaphore_wait(self.sema, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC))) {
      [self.syncdConnection.remoteObjectProxy postEventToSyncServer:event];
      
      // Let em flow
      dispatch_semaphore_signal(self.sema);
    } else {
      LOGI(@"Dropping event %@ from com.google.syncd_queue", event.fileSHA256);
    }
  });
}

- (void)startSyncingEvents {
  dispatch_semaphore_signal(self.sema);
}

- (void)stopSyncingEvents {
  self.sema = dispatch_semaphore_create(0);
}

@end
