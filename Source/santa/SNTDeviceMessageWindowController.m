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

#import "Source/santa/SNTDeviceMessageWindowController.h"

#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeviceEvent.h"
#import "Source/santa/SNTMessageWindow.h"

NS_ASSUME_NONNULL_BEGIN

@interface SNTDeviceMessageWindowController ()
@property(copy, nullable) NSString *customMessage;
@end

@implementation SNTDeviceMessageWindowController

- (instancetype)initWithEvent:(SNTDeviceEvent *)event message:(nullable NSString *)message {
  self = [super initWithWindowNibName:@"DeviceMessageWindow"];
  if (self) {
    _event = event;
    _customMessage = message;
  }
  return self;
}

- (NSAttributedString *)attributedCustomMessage {
  if (self.customMessage) {
    return [SNTBlockMessage formatMessage:self.customMessage];
  }

  if (self.event.remountArgs) {
    return [SNTBlockMessage
      formatMessage:[NSString
                      stringWithFormat:
                        @"The following device was remounted with the following permissions: [%@].",
                        [self.event.remountArgs componentsJoinedByString:@","]]];
  } else {
    return [SNTBlockMessage formatMessage:@"The following device has been blocked from mounting."];
  }
}

- (NSString *)messageHash {
  return self.event.mntonname;
}

@end

NS_ASSUME_NONNULL_END
