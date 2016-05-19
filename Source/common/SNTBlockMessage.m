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

#import "SNTBlockMessage.h"

#import "SNTConfigurator.h"
#import "SNTLogging.h"
#import "SNTStoredEvent.h"

@implementation SNTBlockMessage

+ (NSAttributedString *)attributedBlockMessageForEvent:(SNTStoredEvent *)event
                                         customMessage:(NSString *)customMessage {
  NSString *htmlHeader = @"<html><head><style>"
      @"body {"
      @"  font-family: 'Lucida Grande', 'Helvetica', sans-serif;"
      @"  font-size: 13px;"
      @"  color: #666;"
      @"  text-align: center;"
      @"}"
      @"</style></head><body>";
  NSString *htmlFooter = @"</body></html>";

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

  NSString *fullHTML = [NSString stringWithFormat:@"%@%@%@", htmlHeader, message, htmlFooter];

#ifdef NSAppKitVersionNumber10_0
  NSData *htmlData = [fullHTML dataUsingEncoding:NSUTF8StringEncoding];
  return [[NSAttributedString alloc] initWithHTML:htmlData documentAttributes:NULL];
#else
  NSXMLDocument *xml = [[NSXMLDocument alloc] initWithXMLString:fullHTML options:0 error:NULL];

  // Strip any HTML tags out of the message. Also remove any content inside <style> tags and
  // replace <br> elements with a space while avoiding double-spacing.
  NSString *stripXslt = @"<?xml version='1.0' encoding='utf-8'?>"
    @"<xsl:stylesheet version='1.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform'"
    @"                              xmlns:xhtml='http://www.w3.org/1999/xhtml'>"
    @"<xsl:output method='text'/>"
    @"<xsl:template match='br'><xsl:text>\n</xsl:text></xsl:template>"
    @"<xsl:template match='style'/>"
    @"</xsl:stylesheet>";
  NSError *error;
  NSData *data = [xml objectByApplyingXSLTString:stripXslt arguments:NULL error:&error];
  if (error || ![data isKindOfClass:[NSData class]]) {
    LOGW(@"Error when generating block message: %@", error);
    return [[NSAttributedString alloc] initWithString:@"This binary has been blocked."];
  }
  NSString *strippedString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
  return [[NSAttributedString alloc] initWithString:strippedString];
#endif
}

+ (NSURL *)eventDetailURLForEvent:(SNTStoredEvent *)event {
  SNTConfigurator *config = [SNTConfigurator configurator];

  NSString *formatStr = config.eventDetailURL;
  formatStr = [formatStr stringByReplacingOccurrencesOfString:@"%file_sha%"
                                                   withString:event.fileSHA256];
  formatStr = [formatStr stringByReplacingOccurrencesOfString:@"%username%"
                                                   withString:event.executingUser];
  formatStr = [formatStr stringByReplacingOccurrencesOfString:@"%machine_id%"
                                                   withString:config.machineID];
  return [NSURL URLWithString:formatStr];
}

@end
