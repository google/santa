/// Copyright 2021 Google Inc. All rights reserved.
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
#import <Cocoa/Cocoa.h>

#import "Source/common/SNTDeviceEvent.h"
#import "Source/gui/SNTMessageWindowController.h"

NS_ASSUME_NONNULL_BEGIN

@class SNTStoredEvent;

///
///  Controller for a single message window.
///
@interface SNTDeviceMessageWindowController : SNTMessageWindowController

@property(weak) IBOutlet NSTextField *remountArgsLabel;
@property(weak) IBOutlet NSTextField *remountArgsTitle;

// The device event this window is for.
@property(readonly) SNTDeviceEvent *event;

- (instancetype)initWithEvent:(SNTDeviceEvent *)event message:(nullable NSString *)message;

@end

NS_ASSUME_NONNULL_END
