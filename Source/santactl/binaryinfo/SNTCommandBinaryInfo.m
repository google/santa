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

#import "MOLCertificate.h"
#import "MOLCodesignChecker.h"
#import "SNTFileInfo.h"

@interface SNTCommandBinaryInfo : NSObject<SNTCommand>
@end

@implementation SNTCommandBinaryInfo

REGISTER_COMMAND_NAME(@"binaryinfo")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Prints information about a binary.";
}

+ (NSString *)longHelpText {
  return (@"The details provided will be the same ones Santa uses to make a decision\n"
          @"about binaries. This includes SHA-256, SHA-1, code signing information and\n"
          @"the type of binary.");
}

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  NSString *filePath = [arguments firstObject];

  if (!filePath) {
    printf("Missing file path\n");
    exit(1);
  }

  SNTFileInfo *fileInfo = [[SNTFileInfo alloc] initWithPath:filePath];
  if (!fileInfo) {
    printf("Invalid or empty file\n");
    exit(1);
  }

  NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
  dateFormatter.dateFormat = @"YYYY/MM/dd HH:mm:ss Z";

  [self printKey:@"Path" value:fileInfo.path];
  [self printKey:@"SHA-256" value:fileInfo.SHA256];
  [self printKey:@"SHA-1" value:fileInfo.SHA1];
  [self printKey:@"Bundle Name" value:fileInfo.bundleName];
  [self printKey:@"Bundle Version" value:fileInfo.bundleVersion];
  [self printKey:@"Bundle Version Str" value:fileInfo.bundleShortVersionString];
  [self printKey:@"Download Referer URL" value:fileInfo.quarantineRefererURL];
  [self printKey:@"Download URL" value:fileInfo.quarantineDataURL];
  [self printKey:@"Download Timestamp"
           value:[dateFormatter stringFromDate:fileInfo.quarantineTimestamp]];
  [self printKey:@"Download Agent" value:fileInfo.quarantineAgentBundleID];

  NSArray *archs = [fileInfo architectures];
  if (archs) {
    NSString *s = [NSString stringWithFormat:@"%@ (%@)",
                      fileInfo.machoType, [archs componentsJoinedByString:@", "]];
    [self printKey:@"Type" value:s];
  } else {
    [self printKey:@"Type" value:fileInfo.machoType];
  }

  if ([fileInfo isMissingPageZero]) {
    [self printKey:@"Page Zero" value:@"__PAGEZERO segment missing/bad!"];
  }

  MOLCodesignChecker *csc = [[MOLCodesignChecker alloc] initWithBinaryPath:filePath];
  [self printKey:@"Code-signed" value:(csc) ? @"Yes" : @"No"];
  if (csc) {
    printf("Signing chain:\n");

    [csc.certificates enumerateObjectsUsingBlock:^(MOLCertificate *c,
                                                   unsigned long idx,
                                                   BOOL *stop) {
        printf("    %2lu. %-20s: %s\n", idx + 1, "SHA-256", [c.SHA256 UTF8String]);
        printf("        %-20s: %s\n", "SHA-1", [c.SHA1 UTF8String]);
        printf("        %-20s: %s\n", "Common Name", [c.commonName UTF8String]);
        printf("        %-20s: %s\n", "Organization", [c.orgName UTF8String]);
        printf("        %-20s: %s\n", "Organizational Unit", [c.orgUnit UTF8String]);
        printf("        %-20s: %s\n", "Valid From",
               [[dateFormatter stringFromDate:c.validFrom] UTF8String]);
        printf("        %-20s: %s\n", "Valid Until",
               [[dateFormatter stringFromDate:c.validUntil] UTF8String]);
        printf("\n");
    }];
  }

  exit(0);
}

+ (void)printKey:(NSString *)key value:(NSString *)value {
  printf("%-21s: %s\n", [key UTF8String], [value UTF8String]);
}

@end
