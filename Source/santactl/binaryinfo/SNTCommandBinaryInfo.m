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
    printf("Invalid file\n");
    exit(1);
  }

  printf("%-19s: %s\n", "Path", [[fileInfo path] UTF8String]);
  printf("%-19s: %s\n", "SHA-256", [[fileInfo SHA256] UTF8String]);
  printf("%-19s: %s\n", "SHA-1", [[fileInfo SHA1] UTF8String]);
  printf("%-19s: %s\n", "Bundle Name", [[fileInfo bundleName] UTF8String]);
  printf("%-19s: %s\n", "Bundle Version", [[fileInfo bundleVersion] UTF8String]);
  printf("%-19s: %s\n", "Bundle Version Str", [[fileInfo bundleShortVersionString] UTF8String]);

  NSArray *archs = [fileInfo architectures];
  if (archs) {
    printf("%-19s: %s (%s)\n", "Type",
           [[fileInfo machoType] UTF8String],
           [[archs componentsJoinedByString:@", "] UTF8String]);
  } else {
    printf("%-19s: %s\n", "Type", [[fileInfo machoType] UTF8String]);
  }

  SNTCodesignChecker *csc = [[SNTCodesignChecker alloc] initWithBinaryPath:filePath];

  printf("%-19s: %s\n", "Code-signed", (csc) ? "Yes" : "No");

  if (csc) {
    printf("Signing chain:\n");

    [csc.certificates enumerateObjectsUsingBlock:^(SNTCertificate *c,
                                                   unsigned long idx,
                                                   BOOL *stop) {
        idx++;  // index from 1
        printf("    %2lu. %-20s: %s\n", idx, "SHA-256", [c.SHA256 UTF8String]);
        printf("        %-20s: %s\n", "SHA-1", [c.SHA1 UTF8String]);
        printf("        %-20s: %s\n", "Common Name", [c.commonName UTF8String]);
        printf("        %-20s: %s\n", "Organization", [c.orgName UTF8String]);
        printf("        %-20s: %s\n", "Organizational Unit", [c.orgUnit UTF8String]);
        printf("        %-20s: %s\n", "Valid From", [[c.validFrom description] UTF8String]);
        printf("        %-20s: %s\n", "Valid Until", [[c.validUntil description] UTF8String]);
        printf("\n");
    }];
  }

  exit(0);
}

@end
