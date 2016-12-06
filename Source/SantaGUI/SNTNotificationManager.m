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

#import "SNTBlockMessage.h"
#import "SNTConfigurator.h"
#import "SNTLogging.h"
#import "SNTStoredEvent.h"

@interface SNTNotificationManager ()
///  The currently displayed notification
@property SNTMessageWindowController *currentWindowController;

///  The queue of pending notifications
@property(readonly) NSMutableArray *pendingNotifications;
@end

@implementation SNTNotificationManager

static NSString * const silencedNotificationsKey = @"SilencedNotifications";

- (instancetype)init {
  self = [super init];
  if (self) {
    _pendingNotifications = [[NSMutableArray alloc] init];
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
  } else {
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

#pragma mark SNTNotifierXPC protocol method

- (void)postClientModeNotification:(SNTClientMode)clientmode {
  NSUserNotification *un = [[NSUserNotification alloc] init];
  un.title = @"Santa";
  un.hasActionButton = NO;
  NSString *customMsg;
  switch (clientmode) {
    case SNTClientModeMonitor:
      un.informativeText = @"Switching into Monitor mode";
      customMsg = [[SNTConfigurator configurator] modeNotificationMonitor];
      customMsg = [SNTBlockMessage stringFromHTML:customMsg];
      if (customMsg.length) un.informativeText = customMsg;
      break;
    case SNTClientModeLockdown:
      un.informativeText = @"Switching into Lockdown mode";
      customMsg = [[SNTConfigurator configurator] modeNotificationLockdown];
      customMsg = [SNTBlockMessage stringFromHTML:customMsg];
      if (customMsg.length) un.informativeText = customMsg;
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
    }
  });
}

- (void)postRuleSyncNotificationWithCustomMessage:(NSString *)message {
  NSUserNotification *un = [[NSUserNotification alloc] init];
  un.title = @"Santa";
  un.hasActionButton = NO;
  un.informativeText = message ?: @"Requested rules synced";
  [[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification:un];
}

@end
