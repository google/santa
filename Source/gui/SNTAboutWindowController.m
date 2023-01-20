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

#import "Source/gui/SNTAboutWindowController.h"
#import "Source/gui/SNTAboutWindowView-Swift.h"

#import "Source/common/SNTConfigurator.h"

@implementation SNTAboutWindowController

- (void)showWindow:(id)sender {
  [super showWindow:sender];

  if (self.window) [self.window orderOut:sender];

  self.window =
    [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 0, 0)
                                styleMask:NSWindowStyleMaskClosable | NSWindowStyleMaskTitled
                                  backing:NSBackingStoreBuffered
                                    defer:NO];
  self.window.contentViewController = [SNTAboutWindowViewFactory createWithWindow:self.window];
  self.window.title = @"Santa";
  self.window.delegate = self;
  [self.window makeKeyAndOrderFront:nil];
  [self.window center];

  // Add app to Cmd+Tab and Dock.
  NSApp.activationPolicy = NSApplicationActivationPolicyRegular;
}

- (void)windowWillClose:(NSNotification *)notification {
  // Remove app from Cmd+Tab and Dock.
  NSApp.activationPolicy = NSApplicationActivationPolicyAccessory;
}

@end
