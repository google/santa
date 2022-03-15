/// Copyright 2015 Google Inc. All rights reserved.
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

#import "Source/santa/SNTNotificationManager.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeviceEvent.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santa/SNTMessageWindowController.h"

@interface SNTNotificationManager ()

///  The currently displayed notification
@property SNTMessageWindowController *currentWindowController;

///  The queue of pending notifications
@property(readonly) NSMutableArray *pendingNotifications;

// A serial queue for holding hashBundleBinaries requests
@property dispatch_queue_t hashBundleBinariesQueue;

@end

@implementation SNTNotificationManager

static NSString *const silencedNotificationsKey = @"SilencedNotifications";

- (instancetype)init {
  self = [super init];
  if (self) {
    _pendingNotifications = [[NSMutableArray alloc] init];
    _hashBundleBinariesQueue =
      dispatch_queue_create("com.google.santagui.hashbundlebinaries", DISPATCH_QUEUE_SERIAL);
  }
  return self;
}

- (void)windowDidCloseSilenceHash:(NSString *)hash {
  if (hash) [self updateSilenceDate:[NSDate date] forHash:hash];

  [self.pendingNotifications removeObject:self.currentWindowController];
  self.currentWindowController = nil;

  if ([self.pendingNotifications count]) {
    [self showQueuedWindow];
  } else {
    MOLXPCConnection *bc = [SNTXPCBundleServiceInterface configuredConnection];
    [bc resume];
    [[bc remoteObjectProxy] spindown];
    [bc invalidate];
    [NSApp hide:self];
  }
}

- (void)updateSilenceDate:(NSDate *)date forHash:(NSString *)hash {
  NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
  NSMutableDictionary *d = [[ud objectForKey:silencedNotificationsKey] mutableCopy];
  if (!d) d = [NSMutableDictionary dictionary];
  if (date) {
    d[hash] = date;
  } else {
    [d removeObjectForKey:hash];
  }
  [ud setObject:d forKey:silencedNotificationsKey];
}

- (BOOL)notificationAlreadyQueued:(SNTMessageWindowController *)pendingMsg {
  for (SNTMessageWindowController *msg in self.pendingNotifications) {
    if ([msg messageHash] == [pendingMsg messageHash]) {
      return YES;
    }
  }
  return NO;
}

- (void)queueMessage:(SNTMessageWindowController *)pendingMsg {
  NSString *messageHash = [pendingMsg messageHash];
  if ([self notificationAlreadyQueued:pendingMsg]) return;

  // See if this message is silenced.
  NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
  NSDate *silenceDate = [ud objectForKey:silencedNotificationsKey][messageHash];
  if ([silenceDate isKindOfClass:[NSDate class]]) {
    NSDate *oneDayAgo = [NSDate dateWithTimeIntervalSinceNow:-86400];
    if ([silenceDate compare:[NSDate date]] == NSOrderedDescending) {
      LOGI("Notification silence: date is in the future, ignoring");
      [self updateSilenceDate:nil forHash:messageHash];
    } else if ([silenceDate compare:oneDayAgo] == NSOrderedAscending) {
      LOGI("Notification silence: date is more than one day ago, ignoring");
      [self updateSilenceDate:nil forHash:messageHash];
    } else {
      LOGI("Notification silence: dropping notification for %@", messageHash);
      return;
    }
  }

  pendingMsg.delegate = self;
  [self.pendingNotifications addObject:pendingMsg];

  if (!self.currentWindowController) {
    [self showQueuedWindow];
  }
}

- (void)showQueuedWindow {
  // Notifications arrive on a background thread but UI updates must happen on the main thread.
  // This includes making windows.
  dispatch_async(dispatch_get_main_queue(), ^{
    // If a notification isn't currently being displayed, display the incoming one.
    // This check will generally be redundant, as we'd generally want to check this prior to
    // starting work on the main thread.
    if (!self.currentWindowController) {
      self.currentWindowController = [self.pendingNotifications firstObject];
      [self.currentWindowController showWindow:self];

      if ([self.currentWindowController isKindOfClass:[SNTBinaryMessageWindowController class]]) {
        SNTBinaryMessageWindowController *controller =
          (SNTBinaryMessageWindowController *)self.currentWindowController;
        dispatch_async(self.hashBundleBinariesQueue, ^{
          [self hashBundleBinariesForEvent:controller.event withController:controller];
        });
      }
    }
  });
}

- (void)hashBundleBinariesForEvent:(SNTStoredEvent *)event
                    withController:(SNTBinaryMessageWindowController *)withController {
  withController.foundFileCountLabel.stringValue = @"Searching for files...";

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  MOLXPCConnection *bc = [SNTXPCBundleServiceInterface configuredConnection];
  bc.acceptedHandler = ^{
    dispatch_semaphore_signal(sema);
  };
  [bc resume];

  // Wait a max of 5 secs for the bundle service
  // Otherwise abandon bundle hashing and display the blockable event.
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    [withController updateBlockNotification:event withBundleHash:nil];
    return;
  }

  [[bc remoteObjectProxy] setNotificationListener:self.notificationListener];

  // NSProgress becomes current for this thread. XPC messages vend a child node to the receiver.
  [withController.progress becomeCurrentWithPendingUnitCount:100];

  // Start hashing. Progress is reported to the root NSProgress
  // (currentWindowController.progress).
  [[bc remoteObjectProxy]
    hashBundleBinariesForEvent:event
                         reply:^(NSString *bh, NSArray<SNTStoredEvent *> *events, NSNumber *ms) {
                           // Revert to displaying the blockable event if we fail to calculate the
                           // bundle hash
                           if (!bh)
                             return [withController updateBlockNotification:event
                                                             withBundleHash:nil];

                           event.fileBundleHash = bh;
                           event.fileBundleBinaryCount = @(events.count);
                           event.fileBundleHashMilliseconds = ms;
                           event.fileBundleExecutableRelPath =
                             [events.firstObject fileBundleExecutableRelPath];
                           for (SNTStoredEvent *se in events) {
                             se.fileBundleHash = bh;
                             se.fileBundleBinaryCount = @(events.count);
                             se.fileBundleHashMilliseconds = ms;
                           }

                           // Send the results to santad. It will decide if they need to be
                           // synced.
                           MOLXPCConnection *daemonConn =
                             [SNTXPCControlInterface configuredConnection];
                           [daemonConn resume];
                           [[daemonConn remoteObjectProxy] syncBundleEvent:event
                                                             relatedEvents:events];
                           [daemonConn invalidate];

                           // Update the UI with the bundle hash. Also make the openEventButton
                           // available.
                           [withController updateBlockNotification:event withBundleHash:bh];

                           [bc invalidate];
                         }];

  [withController.progress resignCurrent];
}

#pragma mark SNTNotifierXPC protocol methods

- (void)postClientModeNotification:(SNTClientMode)clientmode {
  NSUserNotification *un = [[NSUserNotification alloc] init];
  un.title = @"Santa";
  un.hasActionButton = NO;
  NSString *customMsg;
  switch (clientmode) {
    case SNTClientModeMonitor:
      un.informativeText = @"Switching into Monitor mode";
      customMsg = [[SNTConfigurator configurator] modeNotificationMonitor];
      if (!customMsg) break;
      if (!customMsg.length) return;
      un.informativeText = [SNTBlockMessage stringFromHTML:customMsg];
      break;
    case SNTClientModeLockdown:
      un.informativeText = @"Switching into Lockdown mode";
      customMsg = [[SNTConfigurator configurator] modeNotificationLockdown];
      if (!customMsg) break;
      if (!customMsg.length) return;
      un.informativeText = [SNTBlockMessage stringFromHTML:customMsg];
      break;
    default: return;
  }
  [[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification:un];
}

- (void)postBlockNotification:(SNTStoredEvent *)event withCustomMessage:(NSString *)message {
  if (!event) {
    LOGI("Error: Missing event object in message received from daemon!");
    return;
  }

  SNTBinaryMessageWindowController *pendingMsg =
    [[SNTBinaryMessageWindowController alloc] initWithEvent:event andMessage:message];

  [self queueMessage:pendingMsg];
}

- (void)postRuleSyncNotificationWithCustomMessage:(NSString *)message {
  NSUserNotification *un = [[NSUserNotification alloc] init];
  un.title = @"Santa";
  un.hasActionButton = NO;
  un.informativeText = message ?: @"Requested application can now be run";
  [[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification:un];
}

- (void)postUSBBlockNotification:(SNTDeviceEvent *)event withCustomMessage:(NSString *)message {
  if (!event) {
    LOGI("Error: Missing event object in message received from daemon!");
    return;
  }
  SNTDeviceMessageWindowController *pendingMsg =
    [[SNTDeviceMessageWindowController alloc] initWithEvent:event message:message];

  [self queueMessage:pendingMsg];
}

#pragma mark SNTBundleNotifierXPC protocol methods

- (void)updateCountsForEvent:(SNTStoredEvent *)event
                 binaryCount:(uint64_t)binaryCount
                   fileCount:(uint64_t)fileCount
                 hashedCount:(uint64_t)hashedCount {
  if ([self.currentWindowController isKindOfClass:[SNTBinaryMessageWindowController class]]) {
    SNTBinaryMessageWindowController *controller =
      (SNTBinaryMessageWindowController *)self.currentWindowController;

    if ([controller.event.idx isEqual:event.idx]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        controller.foundFileCountLabel.stringValue =
          [NSString stringWithFormat:@"%llu binaries / %llu %@", binaryCount,
                                     hashedCount ?: fileCount, hashedCount ? @"hashed" : @"files"];
      });
    }
  }
}

@end
