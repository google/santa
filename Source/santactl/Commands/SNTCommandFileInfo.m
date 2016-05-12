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
#import "SNTRule.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@interface SNTCommandFileInfo : NSObject<SNTCommand>
@end

@implementation SNTCommandFileInfo

REGISTER_COMMAND_NAME(@"fileinfo")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Prints information about a file.";
}

+ (NSString *)longHelpText {
  return (@"The details provided will be the same ones Santa uses to make a decision\n"
          @"about executables. This includes SHA-256, SHA-1, code signing information and\n"
          @"the type of file.");
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
  dateFormatter.dateFormat = @"yyyy/MM/dd HH:mm:ss Z";

  if (isatty(STDOUT_FILENO)) printf("Hashing...");
  NSString *sha1, *sha256;
  [fileInfo hashSHA1:&sha1 SHA256:&sha256];
  if (isatty(STDOUT_FILENO)) printf("\r");

  [self printKey:@"Path" value:fileInfo.path];
  [self printKey:@"SHA-256" value:sha256];
  [self printKey:@"SHA-1" value:sha1];

  if (fileInfo.bundlePath) {
    [self printKey:@"Bundle Name" value:fileInfo.bundleName];
    [self printKey:@"Bundle Version" value:fileInfo.bundleVersion];
    [self printKey:@"Bundle Version Str" value:fileInfo.bundleShortVersionString];
  }

  if (fileInfo.quarantineDataURL) {
    [self printKey:@"Download Referer URL" value:fileInfo.quarantineRefererURL];
    [self printKey:@"Download URL" value:fileInfo.quarantineDataURL];
    [self printKey:@"Download Timestamp"
             value:[dateFormatter stringFromDate:fileInfo.quarantineTimestamp]];
    [self printKey:@"Download Agent" value:fileInfo.quarantineAgentBundleID];
  }

  NSArray *archs = [fileInfo architectures];
  if (archs.count == 0) {
    [self printKey:@"Type" value:[self humanReadableFileType:fileInfo]];
    exit(0);
  }

  NSString *s = [NSString stringWithFormat:@"%@ (%@)",
                                           [self humanReadableFileType:fileInfo],
                                           [archs componentsJoinedByString:@", "]];
  [self printKey:@"Type" value:s];

  if ([fileInfo isMissingPageZero]) {
    [self printKey:@"Page Zero" value:@"__PAGEZERO segment missing/bad!"];
  }

  // Code signature state
  NSError *error;
  MOLCodesignChecker *csc = [[MOLCodesignChecker alloc] initWithBinaryPath:filePath error:&error];
  if (error) {
    switch (error.code) {
      case errSecCSUnsigned:
        [self printKey:@"Code-signed" value:@"No"];
        break;
      case errSecCSSignatureFailed:
      case errSecCSStaticCodeChanged:
      case errSecCSSignatureNotVerifiable:
      case errSecCSSignatureUnsupported:
        [self printKey:@"Code-signed" value:@"Yes, but code/signature changed/unverifiable"];
        break;
      case errSecCSResourceDirectoryFailed:
      case errSecCSResourceNotSupported:
      case errSecCSResourceRulesInvalid:
      case errSecCSResourcesInvalid:
      case errSecCSResourcesNotFound:
      case errSecCSResourcesNotSealed:
        [self printKey:@"Code-signed" value:@"Yes, but resources invalid"];
        break;
      case errSecCSReqFailed:
      case errSecCSReqInvalid:
      case errSecCSReqUnsupported:
        [self printKey:@"Code-signed" value:@"Yes, but failed requirement validation"];
        break;
      case errSecCSInfoPlistFailed:
        [self printKey:@"Code-signed" value:@"Yes, but can't validate as Info.plist is missing"];
        break;
      default: {
        NSString *val = [NSString stringWithFormat:@"Yes, but failed to validate (%ld)",
                         error.code];
        [self printKey:@"Code-signed" value:val];
        break;
      }
    }
  } else if (csc.signatureFlags & kSecCodeSignatureAdhoc) {
    [self printKey:@"Code-signed" value:@"Yes, but ad-hoc"];
  } else {
    [self printKey:@"Code-signed" value:@"Yes"];
  }

  // Binary rule state
  __block SNTRule *r;
  dispatch_group_t group = dispatch_group_create();
  dispatch_group_enter(group);
  [[daemonConn remoteObjectProxy] databaseBinaryRuleForSHA256:sha256 reply:^(SNTRule *rule) {
    if (rule) r = rule;
    dispatch_group_leave(group);
  }];
  NSString *leafCertSHA = [[csc.certificates firstObject] SHA256];
  dispatch_group_enter(group);
  [[daemonConn remoteObjectProxy] databaseCertificateRuleForSHA256:leafCertSHA
                                                             reply:^(SNTRule *rule) {
    if (!r && rule) r = rule;
    dispatch_group_leave(group);
  }];
  if (dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC))) {
    [self printKey:@"Rule" value:@"Cannot communicate with daemon"];
  } else {
    NSString *output;
    switch (r.state) {
      case SNTRuleStateWhitelist:
        output = @"Whitelisted";
        if (isatty(STDOUT_FILENO)) {
          output = @"\033[32mWhitelisted\033[0m";
        }
        [self printKey:@"Rule" value:output];
        break;
      case SNTRuleStateBlacklist:
      case SNTRuleStateSilentBlacklist:
        output = @"Blacklisted";
        if (isatty(STDOUT_FILENO)) {
          output = @"\033[31mBlacklisted\033[0m";
        }
        [self printKey:@"Rule" value:output];
        break;
      default:
        output = @"None";
        if (isatty(STDOUT_FILENO)) {
          output = @"\033[33mNone\033[0m";
        }
        [self printKey:@"Rule" value:output];
    }
  }

  // Signing chain
  if (csc.certificates.count) {
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
  if (!key || !value) return;
  printf("%-21s: %s\n", [key UTF8String], [value UTF8String]);
}

+ (NSString *)humanReadableFileType:(SNTFileInfo *)fi {
  if ([fi isScript]) return @"Script";
  if ([fi isExecutable]) return @"Executable";
  if ([fi isDylib]) return @"Dynamic Library";
  if ([fi isKext]) return @"Kernel Extension";
  if ([fi isXARArchive]) return @"XAR Archive";
  if ([fi isDMG]) return @"Disk Image";
  return @"Unknown";
}

@end
