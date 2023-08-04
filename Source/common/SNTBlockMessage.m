/// Copyright 2016 Google Inc. All rights reserved.
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

#import "Source/common/SNTBlockMessage.h"

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTSystemInfo.h"

@implementation SNTBlockMessage

+ (NSAttributedString *)formatMessage:(NSString *)message {
  NSString *htmlHeader =
    @"<html><head><style>"
    @"body {"
    @"  font-family: 'Lucida Grande', 'Helvetica', sans-serif;"
    @"  font-size: 13px;"
    @"  color: %@;"
    @"  text-align: center;"
    @"}"

    // Supported in beta WebKit. Not sure if it is dynamic when used with NSAttributedString.
    @"@media (prefers-color-scheme: dark) {"
    @"  body {"
    @"    color: #ddd;"
    @"  }"
    @"}"
    @"</style></head><body>";

  // Support Dark Mode. Note, the returned NSAttributedString is static and does not update when
  // the OS switches modes.
  NSString *mode = [NSUserDefaults.standardUserDefaults stringForKey:@"AppleInterfaceStyle"];
  BOOL dark = [mode isEqualToString:@"Dark"];
  htmlHeader = [NSString stringWithFormat:htmlHeader, dark ? @"#ddd" : @"#333"];

  NSString *htmlFooter = @"</body></html>";

  NSString *fullHTML = [NSString stringWithFormat:@"%@%@%@", htmlHeader, message, htmlFooter];

#ifdef SANTAGUI
  NSData *htmlData = [fullHTML dataUsingEncoding:NSUTF8StringEncoding];
  return [[NSAttributedString alloc] initWithHTML:htmlData documentAttributes:NULL];
#else
  NSString *strippedHTML = [self stringFromHTML:fullHTML];
  if (!strippedHTML) {
    return [[NSAttributedString alloc] initWithString:@"This binary has been blocked."];
  }
  return [[NSAttributedString alloc] initWithString:strippedHTML];
#endif
}

+ (NSAttributedString *)attributedBlockMessageForEvent:(SNTStoredEvent *)event
                                         customMessage:(NSString *)customMessage {
  NSString *message;
  if (customMessage.length) {
    message = customMessage;
  } else if (event.decision == SNTEventStateBlockUnknown) {
    message = [[SNTConfigurator configurator] unknownBlockMessage];
    if (!message) {
      message = @"The following application has been blocked from executing<br />"
                @"because its trustworthiness cannot be determined.";
    }
  } else {
    message = [[SNTConfigurator configurator] bannedBlockMessage];
    if (!message) {
      message = @"The following application has been blocked from executing<br />"
                @"because it has been deemed malicious.";
    }
  }
  return [SNTBlockMessage formatMessage:message];
}

+ (NSString *)stringFromHTML:(NSString *)html {
  NSError *error;
  NSXMLDocument *xml = [[NSXMLDocument alloc] initWithXMLString:html options:0 error:&error];

  if (!xml && error.code == NSXMLParserEmptyDocumentError) {
    html = [NSString stringWithFormat:@"<html><body>%@</body></html>", html];
    xml = [[NSXMLDocument alloc] initWithXMLString:html options:0 error:&error];
    if (!xml) return html;
  }

  // Strip any HTML tags out of the message. Also remove any content inside <style> tags and
  // replace <br> elements with a newline.
  NSString *stripXslt =
    @"<?xml version='1.0' encoding='utf-8'?>"
    @"<xsl:stylesheet version='1.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform'"
    @"                              xmlns:xhtml='http://www.w3.org/1999/xhtml'>"
    @"<xsl:output method='text'/>"
    @"<xsl:template match='br'><xsl:text>\n</xsl:text></xsl:template>"
    @"<xsl:template match='style'/>"
    @"</xsl:stylesheet>";
  NSData *data = [xml objectByApplyingXSLTString:stripXslt arguments:NULL error:&error];
  if (error || ![data isKindOfClass:[NSData class]]) {
    return html;
  }
  return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

// Returns either the generated URL for the passed in event, or an NSURL from the passed in custom
// URL string. If the custom URL string is the string "null", nil will be returned. If no custom
// URL is passed and there is no configured EventDetailURL template, nil will be returned.
// The following "format strings" will be replaced in the URL, if they are present:
//
//   %file_identifier%           - The SHA-256 of the binary being executed.
//   %bundle_or_file_identifier% - The hash of the bundle containing this file or the file itself, 
//                                 if no bundle hash is present.
//   %username%                  - The executing user's name.
//   %machine_id%                - The configured machine ID for this host.
//   %hostname%                  - The machine's FQDN.
//   %uuid%                      - The machine's UUID.
//   %serial%                    - The machine's serial number.
//
+ (NSURL *)eventDetailURLForEvent:(SNTStoredEvent *)event customURL:(NSString *)url {
  SNTConfigurator *config = [SNTConfigurator configurator];

  NSString *hostname = [SNTSystemInfo longHostname];
  NSString *uuid = [SNTSystemInfo hardwareUUID];
  NSString *serial = [SNTSystemInfo serialNumber];

  NSString *formatStr = url;
  if (!url.length) formatStr = config.eventDetailURL;
  if (!formatStr.length) return nil;
  if ([formatStr isEqualToString:@"null"]) return nil;

  if (event.fileSHA256) {
    // This key is deprecated, use %file_identifier% or %bundle_or_file_identifier%
    formatStr =
      [formatStr stringByReplacingOccurrencesOfString:@"%file_sha%"
                                           withString:event.fileBundleHash ?: event.fileSHA256];

    formatStr = [formatStr stringByReplacingOccurrencesOfString:@"%file_identifier%"
                                                     withString:event.fileSHA256];
    formatStr =
      [formatStr stringByReplacingOccurrencesOfString:@"%bundle_or_file_identifier%"
                                           withString:event.fileBundleHash ?: event.fileSHA256];
  }
  if (event.executingUser) {
    formatStr = [formatStr stringByReplacingOccurrencesOfString:@"%username%"
                                                     withString:event.executingUser];
  }
  if (config.machineID) {
    formatStr = [formatStr stringByReplacingOccurrencesOfString:@"%machine_id%"
                                                     withString:config.machineID];
  }
  if (hostname.length) {
    formatStr = [formatStr stringByReplacingOccurrencesOfString:@"%hostname%" withString:hostname];
  }
  if (uuid.length) {
    formatStr = [formatStr stringByReplacingOccurrencesOfString:@"%uuid%" withString:uuid];
  }
  if (serial.length) {
    formatStr = [formatStr stringByReplacingOccurrencesOfString:@"%serial%" withString:serial];
  }

  NSURL *u = [NSURL URLWithString:formatStr];
  if (!u) LOGW(@"Unable to generate event detail URL for string '%@'", formatStr);
  return u;
}

@end
