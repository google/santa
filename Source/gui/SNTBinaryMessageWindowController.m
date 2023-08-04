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

#import "Source/gui/SNTBinaryMessageWindowController.h"

#import <MOLCertificate/MOLCertificate.h>
#import <SecurityInterface/SFCertificatePanel.h>

#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredEvent.h"

@interface SNTBinaryMessageWindowController ()
///  The custom message to display for this event
@property(copy) NSString *customMessage;

///  The custom URL to use for this event
@property(copy) NSString *customURL;

///  A 'friendly' string representing the certificate information
@property(readonly, nonatomic) NSString *publisherInfo;

///  An optional message to display with this block.
@property(readonly, nonatomic) NSAttributedString *attributedCustomMessage;

///  Reference to the "Application Name" label in the XIB. Used to remove if application
///  doesn't have a CFBundleName.
@property(weak) IBOutlet NSTextField *applicationNameLabel;

@end

@implementation SNTBinaryMessageWindowController

- (instancetype)initWithEvent:(SNTStoredEvent *)event
                    customMsg:(NSString *)message
                    customURL:(NSString *)url {
  self = [super initWithWindowNibName:@"MessageWindow"];
  if (self) {
    _event = event;
    _customMessage = message;
    _customURL = url;
    _progress = [NSProgress discreteProgressWithTotalUnitCount:1];
    [_progress addObserver:self
                forKeyPath:@"fractionCompleted"
                   options:NSKeyValueObservingOptionNew
                   context:NULL];
  }
  return self;
}

- (void)dealloc {
  [_progress removeObserver:self forKeyPath:@"fractionCompleted"];
}

- (void)observeValueForKeyPath:(NSString *)keyPath
                      ofObject:(id)object
                        change:(NSDictionary *)change
                       context:(void *)context {
  if ([keyPath isEqualToString:@"fractionCompleted"]) {
    dispatch_async(dispatch_get_main_queue(), ^{
      NSProgress *progress = object;
      if (progress.fractionCompleted != 0.0) {
        self.hashingIndicator.indeterminate = NO;
      }
      self.hashingIndicator.doubleValue = progress.fractionCompleted;
    });
  }
}

- (void)loadWindow {
  [super loadWindow];
  NSURL *url = [SNTBlockMessage eventDetailURLForEvent:self.event customURL:self.customURL];

  if (!url) {
    [self.openEventButton removeFromSuperview];
  } else {
    NSString *eventDetailText = [[SNTConfigurator configurator] eventDetailText];
    if (eventDetailText) {
      [self.openEventButton setTitle:eventDetailText];
    }
  }

  if (!self.event.needsBundleHash) {
    [self.bundleHashLabel removeFromSuperview];
    [self.hashingIndicator removeFromSuperview];
    [self.foundFileCountLabel removeFromSuperview];
  } else {
    self.openEventButton.enabled = NO;
    self.hashingIndicator.indeterminate = YES;
    [self.hashingIndicator startAnimation:self];
    self.bundleHashLabel.hidden = YES;
    self.foundFileCountLabel.stringValue = @"";
  }

  if (!self.event.fileBundleName) {
    [self.applicationNameLabel removeFromSuperview];
  }
}

- (NSString *)messageHash {
  return self.event.fileSHA256;
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
  NSURL *url = [SNTBlockMessage eventDetailURLForEvent:self.event customURL:self.customURL];

  [self closeWindow:sender];
  [[NSWorkspace sharedWorkspace] openURL:url];
}

#pragma mark Generated properties

+ (NSSet *)keyPathsForValuesAffectingValueForKey:(NSString *)key {
  if (![key isEqualToString:@"event"]) {
    return [NSSet setWithObject:@"event"];
  } else {
    return [NSSet set];
  }
}

- (NSString *)publisherInfo {
  MOLCertificate *leafCert = [self.event.signingChain firstObject];

  if ([leafCert.commonName isEqualToString:@"Apple Mac OS Application Signing"]) {
    return [NSString stringWithFormat:@"App Store (Team ID: %@)", self.event.teamID];
  } else if (leafCert.commonName && leafCert.orgName) {
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

- (void)updateBlockNotification:(SNTStoredEvent *)event withBundleHash:(NSString *)bundleHash {
  // UI updates must happen on the main thread.
  dispatch_async(dispatch_get_main_queue(), ^{
    if ([self.event.idx isEqual:event.idx]) {
      if (bundleHash) {
        [self.bundleHashLabel setHidden:NO];
      } else {
        [self.bundleHashLabel removeFromSuperview];
        [self.bundleHashTitle removeFromSuperview];
      }
      self.event.fileBundleHash = bundleHash;
      [self.foundFileCountLabel removeFromSuperview];
      [self.hashingIndicator setHidden:YES];
      [self.openEventButton setEnabled:YES];
    }
  });
}

@end
