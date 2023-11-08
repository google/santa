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

#import "Source/gui/SNTNotificationManager.h"

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
#import "Source/gui/SNTBinaryMessageWindowController.h"
#import "Source/gui/SNTDeviceMessageWindowController.h"
#import "Source/gui/SNTFileAccessMessageWindowController.h"
#import "Source/gui/SNTMessageWindowController.h"

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
  // Post a distributed notification, regardless of queue state.
  [self postDistributedNotification:pendingMsg];

  // If GUI is in silent mode, process bundle scanning
  if ([SNTConfigurator configurator].enableSilentMode) {
    // hash bundle with path
    dispatch_async(self.hashBundleBinariesQueue, ^{
      SNTBinaryMessageWindowController *wc = (SNTBinaryMessageWindowController *)pendingMsg;
      [self hashBundleBinariesForEvent:wc.event
        withProgressHandler:^(NSUInteger progressCount) {
          // progress is reported to the distributed notification
          [self postDistributedNotificationWithEvent:wc.event
                                        withProgress:progressCount
                                     withBinaryCount:0
                                       withFileCount:0
                                     withHashedCount:0];
        }
        completionHandler:^(SNTStoredEvent *event, NSString *bundleHash) {
          // event and hash reported to distributed notification
          [self postDistributedNotificationWithEvent:event withBundleHash:bundleHash];
        }];
    });
    return;
  }
  // if there's already a notification queued for
  // this message, don't do anything else.
  if ([self notificationAlreadyQueued:pendingMsg]) return;

  // See if this message has been user-silenced.
  NSString *messageHash = [pendingMsg messageHash];
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

  if (!self.currentWindowController) {
    [self showQueuedWindow];
  }
}

- (void)postDistributedNotificationWithUserInfo:(NSDictionary *)userInfo
                               notificationName:(NSString *)notificationName {
  NSDistributedNotificationCenter *dc = [NSDistributedNotificationCenter defaultCenter];
  [dc postNotificationName:notificationName
                    object:@"com.google.santa"
                  userInfo:userInfo
        deliverImmediately:YES];
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
  NSMutableArray<NSDictionary *> *signingChain =
    [NSMutableArray arrayWithCapacity:wc.event.signingChain.count];
  for (MOLCertificate *cert in wc.event.signingChain) {
    [signingChain addObject:@{
      kCertSHA256 : cert.SHA256 ?: @"",
      kCertCN : cert.commonName ?: @"",
      kCertOrg : cert.orgName ?: @"",
      kCertOU : cert.orgUnit ?: @"",
      kCertValidFrom : @([cert.validFrom timeIntervalSince1970]) ?: @0,
      kCertValidUntil : @([cert.validUntil timeIntervalSince1970]) ?: @0,
    }];
  }
  NSDictionary *userInfo = @{
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
    kSigningChain : signingChain,
  };

  [self postDistributedNotificationWithUserInfo:userInfo
                               notificationName:@"com.google.santa.notification.blockedeexecution"];
}

- (void)postDistributedNotificationWithEvent:(SNTStoredEvent *)event
                              withBundleHash:(NSString *)bundleHash {
  NSDictionary *userInfo = @{
    kFileSHA256 : event.fileSHA256 ?: @"",
    kFilePath : event.filePath ?: @"",
    kFileBundleName : event.fileBundleName ?: @"",
    kFileBundleID : event.fileBundleID ?: @"",
    kFileBundleHash : bundleHash ?: @"",
  };

  [self postDistributedNotificationWithUserInfo:userInfo
                               notificationName:
                                 @"com.google.santa.notification.blockedeexecution.bundlehash"];
}

- (void)postDistributedNotificationWithEvent:(SNTStoredEvent *)event
                                withProgress:(NSUInteger)progressCount
                             withBinaryCount:(NSUInteger)binaryCount
                               withFileCount:(NSUInteger)fileCount
                             withHashedCount:(NSUInteger)hashedCount {
  NSDictionary *userInfo = @{
    kFileBundleProgress : [NSString stringWithFormat:@"%lu", (unsigned long)progressCount],
    kFileBundleBinaryCount : [NSString stringWithFormat:@"%lu", (unsigned long)binaryCount],
    kFileBundleFileCount : [NSString stringWithFormat:@"%lu", (unsigned long)fileCount],
    kFileBundleBinaryHashedCount : [NSString stringWithFormat:@"%lu", (unsigned long)hashedCount],
    kFileSHA256 : event.fileSHA256 ?: @"",
    kFilePath : event.filePath ?: @"",
    kFileBundleName : event.fileBundleName ?: @"",
    kFileBundleID : event.fileBundleID ?: @"",
  };

  [self postDistributedNotificationWithUserInfo:userInfo
                               notificationName:@"com.google.santa.notification.blockedeexecution."
                                                @"bundlehash.progress"];
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
        controller.foundFileCountLabel.stringValue = @"Searching for files...";
        dispatch_async(self.hashBundleBinariesQueue, ^{
          [self hashBundleBinariesForEvent:controller.event
            withProgressHandler:^(NSUInteger progressCount) {
              dispatch_async(dispatch_get_main_queue(), ^{
                //  Progress is reported to the root NSProgress
                [controller.progress becomeCurrentWithPendingUnitCount:progressCount];
              });
            }
            completionHandler:^(SNTStoredEvent *event, NSString *bundleHash) {
              [controller updateBlockNotification:event withBundleHash:bundleHash];
              [controller.progress resignCurrent];
            }];
        });
      }
    }
  });
}

- (void)hashBundleBinariesForEvent:(SNTStoredEvent *)event
               withProgressHandler:(void (^)(NSUInteger progressCount))progressHandler
                 completionHandler:
                   (void (^)(SNTStoredEvent *event, NSString *bundleHash))completionHandler {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  MOLXPCConnection *bc = [SNTXPCBundleServiceInterface configuredConnection];
  bc.acceptedHandler = ^{
    dispatch_semaphore_signal(sema);
  };
  [bc resume];

  // Wait a max of 5 secs for the bundle service
  // Otherwise abandon bundle hashing and display the blockable event.
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    completionHandler(event, nil);
    LOGE(@"Timeout connecting to bundle service");
    return;
  }

  [[bc remoteObjectProxy] setNotificationListener:self.notificationListener];

  // Progress becomes current for this thread. XPC messages vend a child node to the receiver.
  progressHandler(100);

  // Start hashing. Progress is reported
  [[bc remoteObjectProxy]
    hashBundleBinariesForEvent:event
                         reply:^(NSString *bh, NSArray<SNTStoredEvent *> *events, NSNumber *ms) {
                           // Revert to displaying the blockable event if we fail to calculate the
                           // bundle hash
                           if (!bh) return completionHandler(event, nil);

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

                           // Update the completion with the bundle hash.
                           completionHandler(event, bh);

                           [bc invalidate];
                         }];
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

- (void)postBlockNotification:(SNTStoredEvent *)event
            withCustomMessage:(NSString *)message
                 andCustomURL:(NSString *)url {
  if (!event) {
    LOGI(@"Error: Missing event object in message received from daemon!");
    return;
  }

  SNTBinaryMessageWindowController *pendingMsg =
    [[SNTBinaryMessageWindowController alloc] initWithEvent:event customMsg:message customURL:url];

  [self queueMessage:pendingMsg];
}

- (void)postUSBBlockNotification:(SNTDeviceEvent *)event withCustomMessage:(NSString *)message {
  if (!event) {
    LOGI(@"Error: Missing event object in message received from daemon!");
    return;
  }
  SNTDeviceMessageWindowController *pendingMsg =
    [[SNTDeviceMessageWindowController alloc] initWithEvent:event message:message];

  [self queueMessage:pendingMsg];
}

- (void)postFileAccessBlockNotification:(SNTFileAccessEvent *)event
                          customMessage:(NSString *)message
                              customURL:(NSString *)url
                             customText:(NSString *)text API_AVAILABLE(macos(13.0)) {
  if (!event) {
    LOGI(@"Error: Missing event object in message received from daemon!");
    return;
  }

  SNTFileAccessMessageWindowController *pendingMsg =
    [[SNTFileAccessMessageWindowController alloc] initWithEvent:event
                                                  customMessage:message
                                                      customURL:url
                                                     customText:text];

  [self queueMessage:pendingMsg];
}

#pragma mark SNTBundleNotifierXPC protocol methods

- (void)updateCountsForEvent:(SNTStoredEvent *)event
                 binaryCount:(uint64_t)binaryCount
                   fileCount:(uint64_t)fileCount
                 hashedCount:(uint64_t)hashedCount {
  if ([SNTConfigurator configurator].enableSilentMode) {
    NSUInteger percentCount = 0;
    if (hashedCount > 0 && binaryCount > 0) {
      percentCount = hashedCount / binaryCount * 100;
    }
    [self postDistributedNotificationWithEvent:event
                                  withProgress:percentCount
                               withBinaryCount:binaryCount
                                 withFileCount:fileCount
                               withHashedCount:hashedCount];
    return;
  }
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
