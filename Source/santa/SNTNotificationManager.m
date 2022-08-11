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

#import <MOLCertificate/MOLCertificate.h>
#import <MOLXPCConnection/MOLXPCConnection.h>
#import <UserNotifications/UserNotifications.h>

#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeviceEvent.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTSyncConstants.h"
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

  if (self.pendingNotifications.count) {
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
    if ([[msg messageHash] isEqual:[pendingMsg messageHash]]) return YES;
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
      LOGI(@"Notification silence: date is in the future, ignoring");
      [self updateSilenceDate:nil forHash:messageHash];
    } else if ([silenceDate compare:oneDayAgo] == NSOrderedAscending) {
      LOGI(@"Notification silence: date is more than one day ago, ignoring");
      [self updateSilenceDate:nil forHash:messageHash];
    } else {
      LOGI(@"Notification silence: dropping notification for %@", messageHash);
      return;
    }
  }

  pendingMsg.delegate = self;
  [self.pendingNotifications addObject:pendingMsg];
  [self postDistributedNotification:pendingMsg];

  if (!self.currentWindowController) {
    [self showQueuedWindow];
  }
}

// For blocked execution notifications, post an NSDistributedNotificationCenter
// notification with the important details from the stored event. Distributed
// notifications are system-wide broadcasts that can be sent by apps and observed
// from separate processes. This allows users of Santa to write tools that
// perform actions when we block execution, such as trigger management tools or
// display an enterprise-specific UI (which is particularly useful when combined
// with the EnableSilentMode configuration option, to disable Santa's standard UI).
- (void)postDistributedNotification:(SNTMessageWindowController *)pendingMsg {
  if (![pendingMsg isKindOfClass:[SNTBinaryMessageWindowController class]]) {
    return;
  }
  SNTBinaryMessageWindowController *wc = (SNTBinaryMessageWindowController *)pendingMsg;
  NSDistributedNotificationCenter *dc = [NSDistributedNotificationCenter defaultCenter];
  NSMutableDictionary *userInfo = [@{
    kFileSHA256 : wc.event.fileSHA256 ?: @"",
    kFilePath : wc.event.filePath ?: @"",
    kFileBundleName : wc.event.fileBundleName ?: @"",
    kFileBundleID : wc.event.fileBundleID ?: @"",
    kFileBundleVersion : wc.event.fileBundleVersion ?: @"",
    kFileBundleShortVersionString : wc.event.fileBundleVersionString ?: @"",
    kTeamID : wc.event.teamID ?: @"",
    kExecutingUser : wc.event.executingUser ?: @"",
    kExecutionTime : @([wc.event.occurrenceDate timeIntervalSince1970]) ?: @0,
    kPID : wc.event.pid ?: @0,
    kPPID : wc.event.ppid ?: @0,
    kParentName : wc.event.parentName ?: @"",
  } mutableCopy];

  MOLCertificate *leafCert = [wc.event.signingChain firstObject];
  if (leafCert) {
    userInfo[kCertSHA256] = leafCert.SHA256 ?: @"";
    userInfo[kCertCN] = leafCert.commonName ?: @"";
    userInfo[kCertOrg] = leafCert.orgName ?: @"";
    userInfo[kCertOU] = leafCert.orgUnit ?: @"";
    userInfo[kCertValidFrom] = @([leafCert.validFrom timeIntervalSince1970]) ?: @0;
    userInfo[kCertValidUntil] = @([leafCert.validUntil timeIntervalSince1970]) ?: @0;
  }

  [dc postNotificationName:@"com.google.santa.notification.blockedeexecution"
                    object:@"com.google.santa"
                  userInfo:userInfo];
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
    LOGE(@"Timeout connecting to bundle service");
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
  if ([SNTConfigurator configurator].enableSilentMode) return;

  UNUserNotificationCenter *un = [UNUserNotificationCenter currentNotificationCenter];

  UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
  content.title = @"Santa";

  switch (clientmode) {
    case SNTClientModeMonitor: {
      content.body = @"Switching into Monitor mode";
      NSString *customMsg = [[SNTConfigurator configurator] modeNotificationMonitor];
      if (!customMsg) break;
      // If a custom message is added but as an empty string, disable notifications.
      if (!customMsg.length) return;

      content.body = [SNTBlockMessage stringFromHTML:customMsg];
      break;
    }
    case SNTClientModeLockdown: {
      content.body = @"Switching into Lockdown mode";
      NSString *customMsg = [[SNTConfigurator configurator] modeNotificationLockdown];
      if (!customMsg) break;
      // If a custom message is added but as an empty string, disable notifications.
      if (!customMsg.length) return;

      content.body = [SNTBlockMessage stringFromHTML:customMsg];
      break;
    }
    default: return;
  }

  UNNotificationRequest *req =
    [UNNotificationRequest requestWithIdentifier:@"clientModeNotification"
                                         content:content
                                         trigger:nil];

  [un addNotificationRequest:req withCompletionHandler:nil];
}

- (void)postRuleSyncNotificationWithCustomMessage:(NSString *)message {
  if ([SNTConfigurator configurator].enableSilentMode) return;

  UNUserNotificationCenter *un = [UNUserNotificationCenter currentNotificationCenter];

  UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
  content.title = @"Santa";
  content.body = message ?: @"Requested application can now be run";

  NSString *identifier = [NSString stringWithFormat:@"ruleSyncNotification_%@", content.body];

  UNNotificationRequest *req = [UNNotificationRequest requestWithIdentifier:identifier
                                                                    content:content
                                                                    trigger:nil];

  [un addNotificationRequest:req withCompletionHandler:nil];
}

- (void)postBlockNotification:(SNTStoredEvent *)event withCustomMessage:(NSString *)message {
  if ([SNTConfigurator configurator].enableSilentMode) return;

  if (!event) {
    LOGI(@"Error: Missing event object in message received from daemon!");
    return;
  }

  SNTBinaryMessageWindowController *pendingMsg =
    [[SNTBinaryMessageWindowController alloc] initWithEvent:event andMessage:message];

  [self queueMessage:pendingMsg];
}

- (void)postUSBBlockNotification:(SNTDeviceEvent *)event withCustomMessage:(NSString *)message {
  if ([SNTConfigurator configurator].enableSilentMode) return;

  if (!event) {
    LOGI(@"Error: Missing event object in message received from daemon!");
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
