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

@import Cocoa;

@class SNTStoredEvent;

@protocol SNTMessageWindowControllerDelegate
- (void)windowDidCloseSilenceHash:(NSString *)hash;
@end

///
///  Controller for a single message window.
///
@interface SNTMessageWindowController : NSWindowController

- (instancetype)initWithEvent:(SNTStoredEvent *)event andMessage:(NSString *)message;

- (IBAction)showWindow:(id)sender;
- (IBAction)closeWindow:(id)sender;
- (IBAction)showCertInfo:(id)sender;

///  Reference to the "Bundle Hash" label in the XIB. Used to remove if application
///  doesn't have a bundle hash.
@property(weak) IBOutlet NSTextField *bundleHashLabel;

///  Reference to the "Bundle Identifier" label in the XIB. Used to remove if application
///  doesn't have a bundle hash.
@property(weak) IBOutlet NSTextField *bundleHashTitle;

///
/// Is displayed if calculating the bundle hash is taking a bit.
///
@property(weak) IBOutlet NSProgressIndicator *hashingIndicator;

///
/// Is displayed if calculating the bundle hash is taking a bit.
///
@property(weak) IBOutlet NSTextField *foundFileCountLabel;

///
///  Reference to the "Open Event" button in the XIB. Used to either remove the button
///  if it isn't needed or set its title if it is.
///
@property(weak) IBOutlet NSButton *openEventButton;

///
///  The execution event that this window is for
///
@property(readonly) SNTStoredEvent *event;

///
///  The root progress object. Child nodes are vended to santad to report on work being done.
///
@property NSProgress *progress;

///
///  The delegate to inform when the notification is dismissed
///
@property(weak) id<SNTMessageWindowControllerDelegate> delegate;

@end
