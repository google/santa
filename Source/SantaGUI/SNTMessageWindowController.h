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

@class SNTNotificationMessage;

@protocol SNTMessageWindowControllerDelegate
- (void)windowDidClose;
@end

///
///  Controller for a single message window.
///
@interface SNTMessageWindowController : NSWindowController

- (instancetype)initWithEvent:(SNTNotificationMessage *)event;

- (IBAction)showWindow:(id)sender;
- (IBAction)closeWindow:(id)sender;
- (IBAction)showCertInfo:(id)sender;

///
///  The execution event that this window is for
///
@property SNTNotificationMessage *event;

///
///  The delegate to inform when the notification is dismissed
///
@property(weak) id<SNTMessageWindowControllerDelegate> delegate;

///
///  A 'friendly' string representing the certificate information
///
@property(readonly) IBOutlet NSString *binaryCert;

///
///  An optional message to display with this block.
///
@property(readonly) IBOutlet NSAttributedString *attributedCustomMessage;

@end
