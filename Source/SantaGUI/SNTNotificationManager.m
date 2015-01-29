/// Copyright 2014 Google Inc. All rights reserved.
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

#import "SNTNotificationMessage.h"

@interface SNTNotificationManager ()
/// The currently displayed notification
@property SNTMessageWindowController *currentWindowController;

/// The queue of pending notifications
@property(readonly) NSMutableArray *pendingNotifications;
@end

@implementation SNTNotificationManager

- (instancetype)init {
  self = [super init];
  if (self) {
    _pendingNotifications = [[NSMutableArray alloc] init];
  }
  return self;
}

- (void)windowDidClose {
  [self.pendingNotifications removeObject:self.currentWindowController];
  self.currentWindowController = nil;

  if ([self.pendingNotifications count]) {
    self.currentWindowController = [self.pendingNotifications firstObject];
    [self.currentWindowController showWindow:self];
  } else {
    [NSApp hide:self];
  }
}

#pragma mark SNTNotifierXPC protocol methods

- (void)postBlockNotification:(SNTNotificationMessage *)event {
  // See if this binary is already in the list of pending notifications.
  NSPredicate *predicate = [NSPredicate predicateWithFormat:@"event.SHA256==%@", event.SHA256];
  if ([[self.pendingNotifications filteredArrayUsingPredicate:predicate] count]) return;

  // Notifications arrive on a background thread but UI updates must happen on the main thread.
  // This includes making windows.
  [self performSelectorOnMainThread:@selector(postBlockNotificationMainThread:)
                         withObject:event
                      waitUntilDone:NO];
}

- (void)postBlockNotificationMainThread:(SNTNotificationMessage *)event {
  // Create message window
  SNTMessageWindowController *pendingMsg = [[SNTMessageWindowController alloc] initWithEvent:event];
  pendingMsg.delegate = self;
  [self.pendingNotifications addObject:pendingMsg];

  // If a notification isn't currently being displayed, display the incoming one.
  if (!self.currentWindowController) {
    self.currentWindowController = pendingMsg;

    [NSApp activateIgnoringOtherApps:YES];

    // It's quite likely that we're currently on a background thread, and GUI code should always be
    // on main thread. Open the window on the main thread so any code it runs is also.
    [pendingMsg showWindow:nil];
  }
}

@end
