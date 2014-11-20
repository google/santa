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

#import "SNTMessageWindowController.h"

#import <SecurityInterface/SFCertificatePanel.h>

#import "SNTBinaryInfo.h"
#import "SNTCertificate.h"
#import "SNTMessageWindow.h"
#import "SNTNotificationMessage.h"

@implementation SNTMessageWindowController

- (instancetype)initWithEvent:(SNTNotificationMessage *)event {
  self = [super initWithWindowNibName:@"MessageWindow"];
  if (self) {
    _event = event;
    [self.window setMovableByWindowBackground:NO];
    [self.window setLevel:NSPopUpMenuWindowLevel];
    [self.window center];
  }
  return self;
}

- (IBAction)showWindow:(id)sender {
  [(SNTMessageWindow *)self.window fadeIn:sender];
}

- (IBAction)closeWindow:(id)sender {
  [(SNTMessageWindow *)self.window fadeOut:sender];
}

- (void)windowWillClose:(NSNotification *)notification {
  if (self.delegate) [self.delegate windowDidClose];
}

- (IBAction)showCertInfo:(id)sender {
  // SFCertificatePanel expects an NSArray of SecCertificateRef's
  NSMutableArray *certArray = [NSMutableArray arrayWithCapacity:[self.event.certificates count]];
  for (SNTCertificate *cert in self.event.certificates) {
    [certArray addObject:(id)cert.certRef];
  }

  [[[SFCertificatePanel alloc] init] beginSheetForWindow:self.window
                                           modalDelegate:nil
                                          didEndSelector:nil
                                             contextInfo:nil
                                            certificates:certArray
                                               showGroup:YES];
}

#pragma mark Generated properties

+ (NSSet *)keyPathsForValuesAffectingValueForKey:(NSString *)key {
  if (! [key isEqualToString:@"event"]) {
    return [NSSet setWithObject:@"event"];
  } else {
    return nil;
  }
}

- (NSString *)binaryCert {
  SNTCertificate *leafCert = self.event.leafCertificate;

  if (leafCert.commonName && leafCert.orgName) {
    return [NSString stringWithFormat:@"%@ - %@", leafCert.commonName, leafCert.orgName];
  } else if (leafCert.commonName) {
    return leafCert.commonName;
  } else if (leafCert.orgName) {
    return leafCert.orgName;
  } else {
    return nil;
  }
}

- (NSAttributedString *)attributedCustomMessage {
  if (self.event.customMessage) {
    NSString *htmlHeader = @"<html><head><style>"
                           @"body {"
                           @"  font-family: 'Lucida Grande', 'Helvetica', sans-serif;"
                           @"  font-size: 13px;"
                           @"  color: #666;"
                           @"  text-align: center;"
                           @"}"
                           @"</style></head><body>";
    NSString *htmlFooter = @"</body></html>";
    NSString *fullHtml = [NSString stringWithFormat:@"%@%@%@", htmlHeader,
                          self.event.customMessage, htmlFooter];
    NSData *htmlData = [fullHtml dataUsingEncoding:NSUTF8StringEncoding];
    NSAttributedString *returnStr = [[NSAttributedString alloc] initWithHTML:htmlData
                                                          documentAttributes:NULL];
    return returnStr;
  } else {
    return nil;
  }
}

- (NSImage *)bundleIcon {
  SNTBinaryInfo *bi = [[SNTBinaryInfo alloc] initWithPath:self.event.path];

  if (!bi || !bi.bundle) return nil;

  return [[NSWorkspace sharedWorkspace] iconForFile:bi.bundlePath];
}

@end
