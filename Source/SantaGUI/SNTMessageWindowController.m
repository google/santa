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

#import "SNTCertificate.h"
#import "SNTConfigurator.h"
#import "SNTFileInfo.h"
#import "SNTMessageWindow.h"
#import "SNTStoredEvent.h"

@implementation SNTMessageWindowController

- (instancetype)initWithEvent:(SNTStoredEvent *)event andMessage:(NSString *)message {
  self = [super initWithWindowNibName:@"MessageWindow"];
  if (self) {
    _event = event;
    _customMessage = (message != (NSString *)[NSNull null] ? message : nil);
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
  NSMutableArray *certArray = [NSMutableArray arrayWithCapacity:[self.event.signingChain count]];
  for (SNTCertificate *cert in self.event.signingChain) {
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

- (NSString *)shortenedHash {
  return [self.event.fileSHA256 substringWithRange:NSMakeRange(0, 10)];
}

- (NSString *)publisherInfo {
  SNTCertificate *leafCert = [self.event.signingChain firstObject];

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
  NSString *htmlHeader = @"<html><head><style>"
                         @"body {"
                         @"  font-family: 'Lucida Grande', 'Helvetica', sans-serif;"
                         @"  font-size: 13px;"
                         @"  color: #AAA;"
                         @"  text-align: center;"
                         @"}"
                         @"</style></head><body>";
  NSString *htmlFooter = @"</body></html>";

  NSString *message;
  if ([self.customMessage length] > 0) {
    message = self.customMessage;
  } else {
    message = @"The following application has been blocked from executing<br />"
              @"because its trustworthiness cannot be determined.";
  }

  NSString *fullHTML = [NSString stringWithFormat:@"%@%@%@", htmlHeader, message, htmlFooter];

  NSData *htmlData = [fullHTML dataUsingEncoding:NSUTF8StringEncoding];
  NSAttributedString *returnStr = [[NSAttributedString alloc] initWithHTML:htmlData
                                                        documentAttributes:NULL];
  return returnStr;
}

@end
