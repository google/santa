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

#import "Source/gui/SNTDeviceMessageWindowController.h"
#import "Source/gui/SNTDeviceMessageWindowView-Swift.h"

#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeviceEvent.h"

NS_ASSUME_NONNULL_BEGIN

@interface SNTDeviceMessageWindowController ()
@property(copy, nullable) NSString *customMessage;
@end

@implementation SNTDeviceMessageWindowController

- (instancetype)initWithEvent:(SNTDeviceEvent *)event message:(nullable NSString *)message {
  self = [super init];
  if (self) {
    _event = event;
    _customMessage = message;
  }
  return self;
}

- (void)showWindow:(id)sender {
  if (self.window) [self.window orderOut:sender];

  self.window =
    [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 0, 0)
                                styleMask:NSWindowStyleMaskClosable | NSWindowStyleMaskTitled
                                  backing:NSBackingStoreBuffered
                                    defer:NO];
  self.window.contentViewController =
    [SNTDeviceMessageWindowViewFactory createWithWindow:self.window
                                                  event:self.event
                                              customMsg:self.attributedCustomMessage];
  self.window.delegate = self;

  // Add app to Cmd+Tab and Dock.
  NSApp.activationPolicy = NSApplicationActivationPolicyRegular;

  [super showWindow:sender];
}

- (void)windowWillClose:(NSNotification *)notification {
  // Remove app from Cmd+Tab and Dock.
  NSApp.activationPolicy = NSApplicationActivationPolicyAccessory;
  [super windowWillClose:notification];
}

- (NSAttributedString *)attributedCustomMessage {
  return [SNTBlockMessage formatMessage:self.customMessage];
}

- (NSString *)messageHash {
  return self.event.mntonname;
}

@end

NS_ASSUME_NONNULL_END
