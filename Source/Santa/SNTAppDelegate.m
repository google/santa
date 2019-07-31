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

#import "Source/Santa/SNTAppDelegate.h"

#import <SystemExtensions/SystemExtensions.h>

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/Santa/SNTAboutWindowController.h"
#import "Source/Santa/SNTNotificationManager.h"


@interface SNTAppDelegate ()<OSSystemExtensionRequestDelegate>
@property SNTAboutWindowController *aboutWindowController;
@property SNTNotificationManager *notificationManager;
@property MOLXPCConnection *daemonListener;
@property MOLXPCConnection *bundleListener;
@end

@implementation SNTAppDelegate

#pragma mark App Delegate methods

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
  NSProcessInfo *processInfo = [NSProcessInfo processInfo];
  if ([processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){10, 15, 0}]) {
    LOGD(@"Requesting System Extension");
    OSSystemExtensionRequest *req =
        [OSSystemExtensionRequest activationRequestForExtension:@"com.google.santa.daemon"
                                                          queue:dispatch_get_main_queue()];
    req.delegate = self;
    [[OSSystemExtensionManager sharedManager] submitRequest:req];
  }

  [self setupMenu];
  self.notificationManager = [[SNTNotificationManager alloc] init];

  NSNotificationCenter *workspaceNotifications = [[NSWorkspace sharedWorkspace] notificationCenter];

  [workspaceNotifications addObserverForName:NSWorkspaceSessionDidResignActiveNotification
                                      object:nil
                                       queue:[NSOperationQueue currentQueue]
                                  usingBlock:^(NSNotification *note) {
    self.daemonListener.invalidationHandler = nil;
    [self.daemonListener invalidate];
    self.daemonListener = nil;

    self.bundleListener.invalidationHandler = nil;
    [self.bundleListener invalidate];
    self.bundleListener = nil;
  }];
  [workspaceNotifications addObserverForName:NSWorkspaceSessionDidBecomeActiveNotification
                                      object:nil
                                       queue:[NSOperationQueue currentQueue]
                                  usingBlock:^(NSNotification *note) {
    [self attemptDaemonReconnection];
    [self attemptBundleReconnection];
  }];

  [self createDaemonConnection];
  [self createBundleConnection];
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag {
  self.aboutWindowController = [[SNTAboutWindowController alloc] init];
  [self.aboutWindowController showWindow:self];
  return NO;
}

#pragma mark Connection handling

- (void)createDaemonConnection {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  WEAKIFY(self);

  // Create listener for return connection from daemon.
  NSXPCListener *listener = [NSXPCListener anonymousListener];
  self.daemonListener = [[MOLXPCConnection alloc] initServerWithListener:listener];
  self.daemonListener.privilegedInterface = [SNTXPCNotifierInterface notifierInterface];
  self.daemonListener.exportedObject = self.notificationManager;
  self.daemonListener.acceptedHandler = ^{
    dispatch_semaphore_signal(sema);
  };
  self.daemonListener.invalidationHandler = ^{
    STRONGIFY(self);
    [self attemptDaemonReconnection];
  };
  [self.daemonListener resume];

  // Tell daemon to connect back to the above listener.
  MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
  [daemonConn resume];
  [[daemonConn remoteObjectProxy] setNotificationListener:listener.endpoint];
  [daemonConn invalidate];

  // Now wait for the connection to come in.
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    [self attemptDaemonReconnection];
  }
}

- (void)attemptDaemonReconnection {
  self.daemonListener.invalidationHandler = nil;
  [self.daemonListener invalidate];
  [self performSelectorInBackground:@selector(createDaemonConnection) withObject:nil];
}

- (void)createBundleConnection {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  WEAKIFY(self);

  // Create listener for return connection from the bundle service.
  NSXPCListener *listener = [NSXPCListener anonymousListener];
  self.bundleListener = [[MOLXPCConnection alloc] initServerWithListener:listener];
  self.bundleListener.privilegedInterface = [SNTXPCNotifierInterface bundleNotifierInterface];
  self.bundleListener.exportedObject = self.notificationManager;
  self.bundleListener.acceptedHandler = ^{
    dispatch_semaphore_signal(sema);
  };
  self.bundleListener.invalidationHandler = ^{
    STRONGIFY(self);
    [self attemptBundleReconnection];
  };
  [self.bundleListener resume];

  // Tell santabs to connect back to the above listener.
  MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
  [daemonConn resume];
  [[daemonConn remoteObjectProxy] setBundleNotificationListener:listener.endpoint];
  [daemonConn invalidate];

  // Now wait for the connection to come in.
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    [self attemptBundleReconnection];
  }
}

- (void)attemptBundleReconnection {
  self.bundleListener.invalidationHandler = nil;
  [self.bundleListener invalidate];
  [self performSelectorInBackground:@selector(createBundleConnection) withObject:nil];
}

#pragma mark Menu Management

- (void)setupMenu {
  // Whilst the user will never see the menu, having one with the Copy and Select All options
  // allows the shortcuts for these items to work, which is useful for being able to copy
  // information from notifications. The mainMenu must have a nested menu for this to work properly.
  NSMenu *mainMenu = [[NSMenu alloc] init];
  NSMenu *editMenu = [[NSMenu alloc] init];
  [editMenu addItemWithTitle:@"Copy" action:@selector(copy:) keyEquivalent:@"c"];
  [editMenu addItemWithTitle:@"Select All" action:@selector(selectAll:) keyEquivalent:@"a"];
  NSMenuItem *editMenuItem = [[NSMenuItem alloc] init];
  [editMenuItem setSubmenu:editMenu];
  [mainMenu addItem:editMenuItem];
  [NSApp setMainMenu:mainMenu];
}

#pragma mark OSSystemExtensionRequestDelegate

- (OSSystemExtensionReplacementAction)request:(OSSystemExtensionRequest *)request
                  actionForReplacingExtension:(OSSystemExtensionProperties *)existing
                                withExtension:(OSSystemExtensionProperties *)ext {
  LOGD(@"System Extension \"%@\" request for replacement", request.identifier);
  return OSSystemExtensionReplacementActionReplace;
}

- (void)requestNeedsUserApproval:(OSSystemExtensionRequest *)request {
  LOGD(@"System Extension \"%@\" request needs user approval", request.identifier);
}

- (void)request:(OSSystemExtensionRequest *)request didFailWithError:(NSError *)error {
  LOGD(@"System Extension \"%@\" request did fail: %@", request.identifier, error);
}

- (void)request:(OSSystemExtensionRequest *)request
    didFinishWithResult:(OSSystemExtensionRequestResult)result {
  LOGD(@"System Extension \"%@\" request did finish: %ld", request.identifier, (long)result);
}

@end
