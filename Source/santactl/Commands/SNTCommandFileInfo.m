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

@import Foundation;

#import "SNTCommand.h"
#import "SNTCommandController.h"

#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>

#import "SNTCachedDecision.h"
#import "SNTFileInfo.h"
#import "SNTLogging.h"
#import "SNTRule.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

// file info keys
static NSString *const kPath = @"Path";
static NSString *const kBundleName = @"Bundle Name";
static NSString *const kBundleVersion = @"Bundle Version";
static NSString *const kBundleVersionStr = @"Bundle Version Str";
static NSString *const kDownloadReferrerURL = @"Download Referrer URL";
static NSString *const kDownloadURL = @"Download URL";
static NSString *const kDownloadTimestamp = @"Download Timestamp";
static NSString *const kDownloadAgent = @"Download Agent";
static NSString *const kType = @"Type";
static NSString *const kPageZero = @"Page Zero";
static NSString *const kCodeSigned = @"Code-signed";
static NSString *const kRule = @"Rule";
static NSString *const kSigningChain = @"Signing Chain";

// signing chain keys
static NSString *const kCommonName = @"Common Name";
static NSString *const kOrganization = @"Organization";
static NSString *const kOrganizationalUnit = @"Organizational Unit";
static NSString *const kValidFrom = @"Valid From";
static NSString *const kValidUntil = @"Valid Until";

// shared file info & signing chain keys
static NSString *const kSHA256 = @"SHA-256";
static NSString *const kSHA1 = @"SHA-1";

// global json output flag
static BOOL json = NO;

#pragma mark SNTCommandFileInfo

@interface SNTCommandFileInfo : SNTCommand
@property(nonatomic) BOOL prettyOutput;
@property NSArray *fileInfoKeys;
@property NSArray *signingChainKeys;
@end


NSString *printKeyArray(NSArray *array) {
  __block NSMutableString *string = [[NSMutableString alloc] init];
  [array enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
    [string appendString:[NSString stringWithFormat:@"                       \"%@\"\n", obj]];
  }];
  return string;
}

@implementation SNTCommandFileInfo

REGISTER_COMMAND_NAME(@"fileinfo")

#pragma mark SNTCommand protocol methods

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
  return [NSString stringWithFormat:
          @"The details provided will be the same ones Santa uses to make a decision\n"
          @"about executables. This includes SHA-256, SHA-1, code signing information and\n"
          @"the type of file."
          @"\n"
          @"Usage: santactl fileinfo [options] [file-paths]\n"
          @"    --json: output in json format\n"
          @"    --key: search and return this one piece of information\n"
          @"           valid Keys:\n"
          @"%@\n"
          @"           valid keys when using --cert-index:\n"
          @"%@\n"
          @"    --cert-index: an integer corresponding to a certificate of the signing chain\n"
          @"                  1 for the leaf certificate\n"
          @"                  -1 for the root certificate\n"
          @"                  2 and up for the intermediates / root\n"
          @"\n"
          @"Examples: santactl fileinfo --cert-index 1 --key SHA-256 --json /usr/bin/yes\n"
          @"          santactl fileinfo --key SHA-256 --json /usr/bin/yes\n"
          @"          santactl fileinfo /usr/bin/yes /bin/*\n",
          printKeyArray([self fileInfoKeys]),
          printKeyArray([self signingChainKeys])];
}

+ (NSArray *)fileInfoKeys {
  return @[ kPath, kSHA256, kSHA1, kBundleName, kBundleVersion, kBundleVersionStr,
            kDownloadReferrerURL, kDownloadURL, kDownloadTimestamp, kDownloadAgent,
            kType, kPageZero, kCodeSigned, kRule, kSigningChain ];
}

+ (NSArray *)signingChainKeys {
  return @[ kSHA256, kSHA1, kCommonName, kOrganization, kOrganizationalUnit, kValidFrom,
            kValidUntil ];
}

- (instancetype)initWithDaemonConnection:(SNTXPCConnection *)daemonConn {
  self = [super initWithDaemonConnection:daemonConn];
  if (!self) return nil;
  _prettyOutput = isatty(STDOUT_FILENO) && !json;
  return self;
}

- (void)runWithArguments:(NSArray *)arguments {
  if (!arguments.count) [self printErrorUsageAndExit:@"No arguments"];

  NSString *key;
  NSNumber *certIndex;
  NSArray *filePaths;

  [self parseArguments:arguments
                forKey:&key
             certIndex:&certIndex
            jsonOutput:&json
             filePaths:&filePaths];

  NSFileManager *fm = [NSFileManager defaultManager];
  NSString *cwd = [fm currentDirectoryPath];
  for (NSString *path in filePaths) {
    NSString *fullPath = [path stringByStandardizingPath];
    if ([path characterAtIndex:0] != '/') {
      fullPath = [cwd stringByAppendingPathComponent:fullPath];
    }
    [self recurseAtPath:fullPath indent:0];
  }
  exit(0);
}

- (void)recurseAtPath:(NSString *)path indent:(int)indent {
  NSFileManager *fm = [NSFileManager defaultManager];
  BOOL isDir = NO;
  if (![fm fileExistsAtPath:path isDirectory:&isDir]) return;
  if (isDir) {
    NSDirectoryEnumerator<NSString *> * dirEnum = [fm enumeratorAtPath:path];
    for (NSString *file in dirEnum) {
      NSString *filepath = [path stringByAppendingPathComponent:file];
      if ([fm fileExistsAtPath:filepath isDirectory:&isDir] && isDir) {
        if (self.prettyOutput) printf("\033[93m");
        printf("\n%s:\n", [filepath UTF8String]);
        if (self.prettyOutput) printf("\033[0m");
      } else {
        [self processFile:filepath];
      }
    }
  } else {
    [self processFile:path];
  }
}

- (NSString *)ruleForFileInfo:(SNTFileInfo *)fileInfo {
  static dispatch_once_t token;
  dispatch_once(&token, ^{ [self.daemonConn resume]; });
  __block SNTEventState s;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  [[self.daemonConn remoteObjectProxy] decisionForFilePath:fileInfo.path
                                                fileSHA256:fileInfo.SHA256
                                         certificateSHA256:nil
                                                     reply:^(SNTEventState state) {
                                                       s = state;
                                                       dispatch_semaphore_signal(sema);
                                                     }];
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    return @"Cannot communicate with daemon";
  } else {
    NSMutableString *output =
    (SNTEventStateAllow & s) ? @"Whitelisted".mutableCopy : @"Blacklisted".mutableCopy;
    switch (s) {
      case SNTEventStateAllowUnknown:
      case SNTEventStateBlockUnknown:
        [output appendString:@" (Unknown)"];
        break;
      case SNTEventStateAllowBinary:
      case SNTEventStateBlockBinary:
        [output appendString:@" (Binary)"];
        break;
      case SNTEventStateAllowCertificate:
      case SNTEventStateBlockCertificate:
        [output appendString:@" (Certificate)"];
        break;
      case SNTEventStateAllowScope:
      case SNTEventStateBlockScope:
        [output appendString:@" (Scope)"];
        break;
      default:
        output = @"None".mutableCopy;
        break;
    }
    return output.copy;
  }
}

- (void)processFile:(NSString *)path {
  SNTFileInfo *fileInfo = [[SNTFileInfo alloc] initWithResolvedPath:path error:nil];
  printf("path:\t%s\n", [path UTF8String]);
  printf("SHA256:\t%s\n", [fileInfo.SHA256 UTF8String]);
  printf("fileSize:\t%lu\n", fileInfo.fileSize);
  printf("executable:\t%s\n", fileInfo.isExecutable ? "YES" : "NO");
  printf("rule:\t%s\n", [[self ruleForFileInfo:fileInfo] UTF8String]);
}


// We can convert all of this stuff to property vars now.
- (void)parseArguments:(NSArray *)args
                forKey:(NSString **)key
             certIndex:(NSNumber **)certIndex
            jsonOutput:(BOOL *)jsonOutput
             filePaths:(NSArray **)filePaths {
  __block NSMutableArray *paths = [[NSMutableArray alloc] init];
  [args enumerateObjectsUsingBlock:^(NSString *obj, NSUInteger idx, BOOL *stop) {
    if ([obj caseInsensitiveCompare:@"--json"] == NSOrderedSame) {
      *jsonOutput = YES;
    } else if ([obj caseInsensitiveCompare:@"--cert-index"] == NSOrderedSame) {
      if (++idx > args.count - 1 || [args[idx] hasPrefix:@"--"]) {
        [self printErrorUsageAndExit:@"\n--cert-index requires an argument"];
      }
      *certIndex = @([args[idx] integerValue]);
    } else if ([obj caseInsensitiveCompare:@"--key"] == NSOrderedSame) {
      if (++idx > args.count - 1 || [args[idx] hasPrefix:@"--"]) {
        [self printErrorUsageAndExit:@"\n--key requires an argument"];
      }
      *key = args[idx];
    } else if ([@([obj integerValue]) isEqual:*certIndex] || [obj isEqual:*key]) {
      return;
    } else {
      [paths addObject:args[idx]];
    }
  }];
  if (*key && !*certIndex && ![[[self class] fileInfoKeys] containsObject:*key]) {
    [self printErrorUsageAndExit:
        [NSString stringWithFormat:@"\n\"%@\" is an invalid key", *key]];
  } else if (*key && *certIndex && ![[[self class] signingChainKeys] containsObject:*key]) {
    [self printErrorUsageAndExit:
        [NSString stringWithFormat:@"\n\"%@\" is an invalid key when using --cert-index", *key]];
  } else if ([@(0) isEqual:*certIndex]) {
    [self printErrorUsageAndExit:@"\n0 is an invalid --cert-index\n  --cert-index is 1 indexed"];
  }
  if (!paths.count) [self printErrorUsageAndExit:@"\nat least one file-path is needed"];
  *filePaths = paths.copy;
}

                         
@end
