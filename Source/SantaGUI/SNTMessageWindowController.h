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

@class SNTStoredEvent;

@protocol SNTMessageWindowControllerDelegate
- (void)windowDidClose;
@end

///
///  Controller for a single message window.
///
@interface SNTMessageWindowController : NSWindowController

- (instancetype)initWithEvent:(SNTStoredEvent *)event andMessage:(NSString *)message;

- (IBAction)showWindow:(id)sender;
- (IBAction)closeWindow:(id)sender;
- (IBAction)showCertInfo:(id)sender;

///
///  The execution event that this window is for
///
@property SNTStoredEvent *event;

///
///  The custom message to display for this event
///
@property(copy) NSString *customMessage;

///
///  The delegate to inform when the notification is dismissed
///
@property(weak) id<SNTMessageWindowControllerDelegate> delegate;

///
///  A 'friendly' string representing the certificate information
///
@property(readonly, nonatomic) NSString *publisherInfo;

///
///  An optional message to display with this block.
///
@property(readonly, nonatomic) NSAttributedString *attributedCustomMessage;

///
///  Reference to the "Open Event" button in the XIB. Used to either remove the button
///  if it isn't needed or set its title if it is.
///
@property IBOutlet NSButton *openEventButton;

@end
