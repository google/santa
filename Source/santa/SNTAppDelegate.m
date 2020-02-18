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

#import "Source/santa/SNTAppDelegate.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import <SystemExtensions/SystemExtensions.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santa/SNTAboutWindowController.h"
#import "Source/santa/SNTNotificationManager.h"

@interface SNTAppDelegate ()<OSSystemExtensionRequestDelegate>
@property SNTAboutWindowController *aboutWindowController;
@property SNTNotificationManager *notificationManager;
@property MOLXPCConnection *daemonListener;
@end

@implementation SNTAppDelegate

#pragma mark App Delegate methods

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
  if (@available(macOS 10.15, *)) {
    [self loadSystemExtension];
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
  }];
  [workspaceNotifications addObserverForName:NSWorkspaceSessionDidBecomeActiveNotification
                                      object:nil
                                       queue:[NSOperationQueue currentQueue]
                                  usingBlock:^(NSNotification *note) {
    [self attemptDaemonReconnection];
  }];

  [self createDaemonConnection];
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag {
  self.aboutWindowController = [[SNTAboutWindowController alloc] init];
  [self.aboutWindowController showWindow:self];
  return NO;
}

- (void)loadSystemExtension API_AVAILABLE(macos(10.15)) {
  if (![[SNTConfigurator configurator] enableSystemExtension]) {
    LOGI(@"EnableSystemExtension is disabled");
    return;
  }
  LOGI(@"Requesting SystemExtension activation");
  NSString *e = [SNTXPCControlInterface systemExtensionID];
  dispatch_queue_t q = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0);
  OSSystemExtensionRequest *req = [OSSystemExtensionRequest activationRequestForExtension:e
                                                                                    queue:q];
  req.delegate = self;
  [[OSSystemExtensionManager sharedManager] submitRequest:req];
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

  // This listener will also handle bundle service requests to update the GUI.
  // When initializing connections with santabundleservice, the notification manager
  // will send along the endpoint so santabundleservice knows where to find us.
  self.notificationManager.notificationListener = listener.endpoint;

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
                  actionForReplacingExtension:(OSSystemExtensionProperties *)old
                                withExtension:(OSSystemExtensionProperties *)new
    API_AVAILABLE(macos(10.15)) {
  LOGI(@"SystemExtension \"%@\" request for replacement", request.identifier);
  return OSSystemExtensionReplacementActionReplace;
}

- (void)requestNeedsUserApproval:(OSSystemExtensionRequest *)request API_AVAILABLE(macos(10.15)) {
  LOGI(@"SystemExtension \"%@\" request needs user approval", request.identifier);
}

- (void)request:(OSSystemExtensionRequest *)request
    didFailWithError:(NSError *)error API_AVAILABLE(macos(10.15)) {
  LOGI(@"SystemExtension \"%@\" request did fail: %@", request.identifier, error);
}

- (void)request:(OSSystemExtensionRequest *)request
    didFinishWithResult:(OSSystemExtensionRequestResult)result API_AVAILABLE(macos(10.15)) {
  LOGI(@"SystemExtension \"%@\" request did finish: %ld", request.identifier, (long)result);
}

@end
