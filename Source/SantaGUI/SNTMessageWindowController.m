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

#import "SNTMessageWindowController.h"

#import <SecurityInterface/SFCertificatePanel.h>

#import "MOLCertificate.h"
#import "SNTBlockMessage.h"
#import "SNTConfigurator.h"
#import "SNTFileInfo.h"
#import "SNTMessageWindow.h"
#import "SNTStoredEvent.h"

@interface SNTMessageWindowController ()
///  The execution event that this window is for
@property SNTStoredEvent *event;

///  The custom message to display for this event
@property(copy) NSString *customMessage;

///  A 'friendly' string representing the certificate information
@property(readonly, nonatomic) NSString *publisherInfo;

///  An optional message to display with this block.
@property(readonly, nonatomic) NSAttributedString *attributedCustomMessage;

///  Reference to the "Open Event" button in the XIB. Used to either remove the button
///  if it isn't needed or set its title if it is.
@property IBOutlet NSButton *openEventButton;

///  Reference to the "Application Name" label in the XIB. Used to remove if application
///  doesn't have a CFBundleName.
@property IBOutlet NSTextField *applicationNameLabel;

///  Linked to checkbox in UI to prevent future notifications for this binary.
@property BOOL silenceFutureNotifications;
@end

@implementation SNTMessageWindowController

- (instancetype)initWithEvent:(SNTStoredEvent *)event andMessage:(NSString *)message {
  self = [super initWithWindowNibName:@"MessageWindow"];
  if (self) {
    _event = event;
    _customMessage = message;
  }
  return self;
}

- (void)loadWindow {
  [super loadWindow];
  [self.window setLevel:NSPopUpMenuWindowLevel];
  [self.window setMovableByWindowBackground:YES];

  if (![[SNTConfigurator configurator] eventDetailURL]) {
    [self.openEventButton removeFromSuperview];
  } else {
    NSString *eventDetailText = [[SNTConfigurator configurator] eventDetailText];
    if (eventDetailText) {
      [self.openEventButton setTitle:eventDetailText];
    }
  }

  if (!self.event.fileBundleName) {
    [self.applicationNameLabel removeFromSuperview];
  }
}

- (IBAction)showWindow:(id)sender {
  [(SNTMessageWindow *)self.window fadeIn:sender];
}

- (IBAction)closeWindow:(id)sender {
  [(SNTMessageWindow *)self.window fadeOut:sender];
}

- (void)windowWillClose:(NSNotification *)notification {
  if (!self.delegate) return;

  if (self.silenceFutureNotifications) {
    [self.delegate windowDidCloseSilenceHash:self.event.fileSHA256];
  } else {
    [self.delegate windowDidCloseSilenceHash:nil];
  }
}

- (IBAction)showCertInfo:(id)sender {
  // SFCertificatePanel expects an NSArray of SecCertificateRef's
  NSMutableArray *certArray = [NSMutableArray arrayWithCapacity:[self.event.signingChain count]];
  for (MOLCertificate *cert in self.event.signingChain) {
    [certArray addObject:(id)cert.certRef];
  }

  [[[SFCertificatePanel alloc] init] beginSheetForWindow:self.window
                                           modalDelegate:nil
                                          didEndSelector:nil
                                             contextInfo:nil
                                            certificates:certArray
                                               showGroup:YES];
}

- (IBAction)openEventDetails:(id)sender {
  SNTConfigurator *config = [SNTConfigurator configurator];

  NSString *formatStr = config.eventDetailURL;
  formatStr = [formatStr stringByReplacingOccurrencesOfString:@"%file_sha%"
                                                   withString:self.event.fileSHA256];
  formatStr = [formatStr stringByReplacingOccurrencesOfString:@"%username%"
                                                   withString:self.event.executingUser];
  formatStr = [formatStr stringByReplacingOccurrencesOfString:@"%machine_id%"
                                                   withString:config.machineID];

  [self closeWindow:sender];
  [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:formatStr]];
}

#pragma mark Generated properties

+ (NSSet *)keyPathsForValuesAffectingValueForKey:(NSString *)key {
  if (![key isEqualToString:@"event"]) {
    return [NSSet setWithObject:@"event"];
  } else {
    return nil;
  }
}

- (NSString *)publisherInfo {
  MOLCertificate *leafCert = [self.event.signingChain firstObject];

  if (leafCert.commonName && leafCert.orgName) {
    return [NSString stringWithFormat:@"%@ - %@", leafCert.orgName, leafCert.commonName];
  } else if (leafCert.commonName) {
    return leafCert.commonName;
  } else if (leafCert.orgName) {
    return leafCert.orgName;
  } else {
    return nil;
  }
}

- (NSAttributedString *)attributedCustomMessage {
  return [SNTBlockMessage attributedBlockMessageForEvent:self.event
                                           customMessage:self.customMessage];
}

@end
