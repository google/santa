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

#import "SNTCommandController.h"

#include "SNTLogging.h"

#import "SNTCertificate.h"
#import "SNTCodesignChecker.h"
#import "SNTFileInfo.h"

@interface SNTCommandBinaryInfo : NSObject<SNTCommand>
@end

@implementation SNTCommandBinaryInfo

REGISTER_COMMAND_NAME(@"binaryinfo");

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Prints information about the given binary.";
}

+ (NSString *)longHelpText {
  return (@"The details provided will be the same ones Santa uses to make a decision about binaries"
          @"This includes SHA-1, SHA-256, code signing information and the type of binary");
}

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  NSString *filePath = [arguments firstObject];

  if (!filePath) {
    LOGI(@"Missing file path");
    exit(1);
  }

  SNTFileInfo *fileInfo = [[SNTFileInfo alloc] initWithPath:filePath];
  if (!fileInfo) {
    LOGI(@"Invalid file");
    exit(1);
  }

  LOGI(@"Info for file: %@", [fileInfo path]);
  LOGI(@"-----------------------------------------------------------");
  LOGI(@"%-20s: %@", "SHA-1", [fileInfo SHA1]);
  LOGI(@"%-20s: %@", "SHA-256", [fileInfo SHA256]);

  NSArray *archs = [fileInfo architectures];
  if (archs) {
    LOGI(@"%-20s: %@ (%@)", "Type", [fileInfo machoType], [archs componentsJoinedByString:@", "]);
  } else {
    LOGI(@"%-20s: %@", "Type", [fileInfo machoType]);
  }

  SNTCodesignChecker *csc = [[SNTCodesignChecker alloc] initWithBinaryPath:filePath];

  LOGI(@"%-20s: %s", "Code-signed", (csc) ? "Yes" : "No");

  if (csc) {
    LOGI(@"Signing chain\n");

    [csc.certificates enumerateObjectsUsingBlock:^(SNTCertificate *c,
                                                   unsigned long idx,
                                                   BOOL *stop) {
        idx++;  // index from 1
        LOGI(@"    %2lu. %-20s: %@", idx, "SHA-1", c.SHA1);
        LOGI(@"        %-20s: %@", "Common Name", c.commonName);
        LOGI(@"        %-20s: %@", "Organization", c.orgName);
        LOGI(@"        %-20s: %@", "Organizational Unit", c.orgUnit);
        LOGI(@"        %-20s: %@", "Valid From", c.validFrom);
        LOGI(@"        %-20s: %@", "Valid Until", c.validUntil);
        LOGI(@"");
    }];
  }

  exit(0);
}

@end
