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

#import "SNTNotificationManager.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "SNTBlockMessage.h"
#import "SNTConfigurator.h"
#import "SNTLogging.h"
#import "SNTStoredEvent.h"
#import "SNTStrengthify.h"
#import "SNTXPCControlInterface.h"

@interface SNTNotificationManager ()

///  The currently displayed notification
@property SNTMessageWindowController *currentWindowController;

///  The queue of pending notifications
@property(readonly) NSMutableArray *pendingNotifications;

///  The connection to the bundle service
@property MOLXPCConnection *bundleServiceConnection;

///  A semaphore to block bundle hashing until a connection is established
@property dispatch_semaphore_t bundleServiceSema;

// A serial queue for holding hashBundleBinaries requests
@property dispatch_queue_t hashBundleBinariesQueue;

@end

@implementation SNTNotificationManager

static NSString * const silencedNotificationsKey = @"SilencedNotifications";

- (instancetype)init {
  self = [super init];
  if (self) {
    _pendingNotifications = [[NSMutableArray alloc] init];
    _bundleServiceSema = dispatch_semaphore_create(0);
    _hashBundleBinariesQueue = dispatch_queue_create("com.google.santagui.hashbundlebinaries",
                                                     DISPATCH_QUEUE_SERIAL);
  }
  return self;
}

- (void)windowDidCloseSilenceHash:(NSString *)hash {
  if (hash) [self updateSilenceDate:[NSDate date] forHash:hash];

  [self.pendingNotifications removeObject:self.currentWindowController];
  self.currentWindowController = nil;

  if ([self.pendingNotifications count]) {
    self.currentWindowController = [self.pendingNotifications firstObject];
    [self.currentWindowController showWindow:self];
    if (self.currentWindowController.event.needsBundleHash) {
      dispatch_async(self.hashBundleBinariesQueue, ^{
        [self hashBundleBinariesForEvent:self.currentWindowController.event];
      });
    }
  } else {
    // Tear down the bundle service
    self.bundleServiceSema = dispatch_semaphore_create(0);
    [self.bundleServiceConnection invalidate];
    self.bundleServiceConnection = nil;
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
    default:
      return;
  }
  [[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification:un];
}

- (void)postBlockNotification:(SNTStoredEvent *)event withCustomMessage:(NSString *)message {
  // See if this binary is already in the list of pending notifications.
  NSPredicate *predicate =
      [NSPredicate predicateWithFormat:@"event.fileSHA256==%@", event.fileSHA256];
  if ([[self.pendingNotifications filteredArrayUsingPredicate:predicate] count]) return;

  // See if this binary is silenced.
  NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
  NSDate *silenceDate = [ud objectForKey:silencedNotificationsKey][event.fileSHA256];
  if ([silenceDate isKindOfClass:[NSDate class]]) {
    NSDate *oneDayAgo = [NSDate dateWithTimeIntervalSinceNow:-86400];
    if ([silenceDate compare:[NSDate date]] == NSOrderedDescending) {
      LOGI(@"Notification silence: date is in the future, ignoring");
      [self updateSilenceDate:nil forHash:event.fileSHA256];
    } else if ([silenceDate compare:oneDayAgo] == NSOrderedAscending) {
      LOGI(@"Notification silence: date is more than one day ago, ignoring");
      [self updateSilenceDate:nil forHash:event.fileSHA256];
    } else {
      LOGI(@"Notification silence: dropping notification for %@", event.fileSHA256);
      return;
    }
  }

  if (!event) {
    LOGI(@"Error: Missing event object in message received from daemon!");
    return;
  }

  // Notifications arrive on a background thread but UI updates must happen on the main thread.
  // This includes making windows.
  dispatch_async(dispatch_get_main_queue(), ^{
    SNTMessageWindowController *pendingMsg =
        [[SNTMessageWindowController alloc] initWithEvent:event andMessage:message];
    pendingMsg.delegate = self;
    [self.pendingNotifications addObject:pendingMsg];

    // If a notification isn't currently being displayed, display the incoming one.
    if (!self.currentWindowController) {
      self.currentWindowController = pendingMsg;
      [pendingMsg showWindow:nil];
      if (self.currentWindowController.event.needsBundleHash) {
        dispatch_async(self.hashBundleBinariesQueue, ^{
          [self hashBundleBinariesForEvent:self.currentWindowController.event];
        });
      }
    }
  });
}

- (void)postRuleSyncNotificationWithCustomMessage:(NSString *)message {
  NSUserNotification *un = [[NSUserNotification alloc] init];
  un.title = @"Santa";
  un.hasActionButton = NO;
  un.informativeText = message ?: @"Requested application can now be run";
  [[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification:un];
}

#pragma mark SNTBundleNotifierXPC protocol methods

- (void)updateCountsForEvent:(SNTStoredEvent *)event
                 binaryCount:(uint64_t)binaryCount
                   fileCount:(uint64_t)fileCount
                 hashedCount:(uint64_t)hashedCount {
  if ([self.currentWindowController.event.idx isEqual:event.idx]) {
    dispatch_async(dispatch_get_main_queue(), ^{
      self.currentWindowController.foundFileCountLabel.stringValue =
          [NSString stringWithFormat:@"%llu binaries / %llu %@",
               binaryCount, hashedCount ?: fileCount, hashedCount ? @"hashed" : @"files"];
    });
  }
}

- (void)setBundleServiceListener:(NSXPCListenerEndpoint *)listener {
  MOLXPCConnection *c = [[MOLXPCConnection alloc] initClientWithListener:listener];
  c.remoteInterface = [SNTXPCBundleServiceInterface bundleServiceInterface];
  [c resume];
  self.bundleServiceConnection = c;

  WEAKIFY(self);
  self.bundleServiceConnection.invalidationHandler = ^{
    STRONGIFY(self);
    if (self.currentWindowController) {
      [self updateBlockNotification:self.currentWindowController.event withBundleHash:nil];
    }
    self.bundleServiceConnection.invalidationHandler = nil;
    [self.bundleServiceConnection invalidate];
  };

  dispatch_semaphore_signal(self.bundleServiceSema);
}

#pragma mark SNTBundleNotifierXPC helper methods

- (void)hashBundleBinariesForEvent:(SNTStoredEvent *)event {
  self.currentWindowController.foundFileCountLabel.stringValue = @"Searching for files...";

  // Wait a max of 6 secs for the bundle service. Should the bundle service fall over, it will
  // reconnect within 5 secs. Otherwise abandon bundle hashing and display the blockable event.
  if (dispatch_semaphore_wait(self.bundleServiceSema,
                              dispatch_time(DISPATCH_TIME_NOW, 6 * NSEC_PER_SEC))) {
    [self updateBlockNotification:event withBundleHash:nil];
    return;
  }

  // Let all future requests flow, until the connection is terminated and we go back to waiting.
  dispatch_semaphore_signal(self.bundleServiceSema);

  // NSProgress becomes current for this thread. XPC messages vend a child node to the receiver.
  [self.currentWindowController.progress becomeCurrentWithPendingUnitCount:100];

  // Start hashing. Progress is reported to the root NSProgress (currentWindowController.progress).
  [[self.bundleServiceConnection remoteObjectProxy]
      hashBundleBinariesForEvent:event
                           reply:^(NSString *bh, NSArray<SNTStoredEvent *> *events, NSNumber *ms) {
    // Revert to displaying the blockable event if we fail to calculate the bundle hash
    if (!bh) return [self updateBlockNotification:event withBundleHash:nil];

    event.fileBundleHash = bh;
    event.fileBundleBinaryCount = @(events.count);
    event.fileBundleHashMilliseconds = ms;
    event.fileBundleExecutableRelPath = [events.firstObject fileBundleExecutableRelPath];
    for (SNTStoredEvent *se in events) {
      se.fileBundleHash = bh;
      se.fileBundleBinaryCount = @(events.count);
      se.fileBundleHashMilliseconds = ms;
    }

    // Send the results to santad. It will decide if they need to be synced.
    MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
    [daemonConn resume];
    [[daemonConn remoteObjectProxy] syncBundleEvent:event relatedEvents:events];
    [daemonConn invalidate];

    // Update the UI with the bundle hash. Also make the openEventButton available.
    [self updateBlockNotification:event withBundleHash:bh];
  }];
  [self.currentWindowController.progress resignCurrent];
}

- (void)updateBlockNotification:(SNTStoredEvent *)event withBundleHash:(NSString *)bundleHash {
  dispatch_async(dispatch_get_main_queue(), ^{
    if ([self.currentWindowController.event.idx isEqual:event.idx]) {
      if (bundleHash) {
        [self.currentWindowController.bundleHashLabel setHidden:NO];
      } else {
        [self.currentWindowController.bundleHashLabel removeFromSuperview];
        [self.currentWindowController.bundleHashTitle removeFromSuperview];
      }
      self.currentWindowController.event.fileBundleHash = bundleHash;
      [self.currentWindowController.foundFileCountLabel removeFromSuperview];
      [self.currentWindowController.hashingIndicator setHidden:YES];
      [self.currentWindowController.openEventButton setEnabled:YES];
    }
  });
}

@end
