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
#import "Source/common/SNTStoredEvent.h"

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCProxyInterface.h"
#import "Source/Santa/SNTAboutWindowController.h"
#import "Source/Santa/SNTNotificationManager.h"


@interface SNTAppDelegate ()<OSSystemExtensionRequestDelegate>
@property SNTAboutWindowController *aboutWindowController;
@property SNTNotificationManager *notificationManager;
@property MOLXPCConnection *server;
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
    [self unregisterServer];
  }];
  [workspaceNotifications addObserverForName:NSWorkspaceSessionDidBecomeActiveNotification
                                      object:nil
                                       queue:[NSOperationQueue currentQueue]
                                  usingBlock:^(NSNotification *note) {
    [self registerServer];
  }];

  [self registerServer];
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag {
  self.aboutWindowController = [[SNTAboutWindowController alloc] init];
  [self.aboutWindowController showWindow:self];
  return NO;
}

- (void)registerServer {
  NSXPCListener *listener = [NSXPCListener anonymousListener];
  self.server = [[MOLXPCConnection alloc] initServerWithListener:listener];
  self.server.unprivilegedInterface = [SNTXPCNotifierInterface notifierInterface];
  self.server.privilegedInterface = self.server.unprivilegedInterface;
  self.server.exportedObject = self;
  [self.server resume];

  MOLXPCConnection *proxy = [SNTXPCProxyInterface configuredConnection];
  [proxy.remoteObjectProxy registerListener:listener.endpoint ofType:SNTXPCTypeGUI];
}

- (void)unregisterServer {
  MOLXPCConnection *proxy = [SNTXPCProxyInterface configuredConnection];
  [proxy.remoteObjectProxy removeListenerOfType:SNTXPCTypeGUI];
  self.server.invalidationHandler = nil;
  [self.server invalidate];
  self.server = nil;
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
