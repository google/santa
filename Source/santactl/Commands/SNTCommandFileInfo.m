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
@import AppKit;

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

// Used by longHelpText to display a list of valid keys passed in as an array.
NSString *formattedStringForKeyArray(NSArray<NSString *> *array) {
  NSMutableString *result = [[NSMutableString alloc] init];
  for (NSString *key in array) {
    [result appendString:[NSString stringWithFormat:@"                       \"%@\"\n", key]];
  }
  return result;
}

@interface SNTCommandFileInfo : SNTCommand

// Properties set from commandline flags
@property BOOL recursive;
@property BOOL jsonOutput;
@property NSNumber *certIndex;
@property NSArray<NSString *> *outputKeyList;
@property NSString *directoryColor;

@property(readonly, nonatomic) BOOL prettyOutput;
@property(nonatomic) BOOL hadPreviousEntry; // used when printing info for multiple files
@property(nonatomic) BOOL daemonUnavailable;
@property(readonly, nonatomic) NSArray<NSString *> *fileInfoKeys;
@property(readonly, nonatomic) NSArray<NSString *> *signingChainKeys;

// Block type to be used with propertyMap values
typedef id (^SNTAttributeBlock)(SNTFileInfo *);

// on read generated properties
@property(readonly, copy, nonatomic) SNTAttributeBlock path;
@property(readonly, copy, nonatomic) SNTAttributeBlock sha256;
@property(readonly, copy, nonatomic) SNTAttributeBlock sha1;
@property(readonly, copy, nonatomic) SNTAttributeBlock bundleName;
@property(readonly, copy, nonatomic) SNTAttributeBlock bundleVersion;
@property(readonly, copy, nonatomic) SNTAttributeBlock bundleShortVersionString;
@property(readonly, copy, nonatomic) SNTAttributeBlock downloadReferrerURL;
@property(readonly, copy, nonatomic) SNTAttributeBlock downloadURL;
@property(readonly, copy, nonatomic) SNTAttributeBlock downloadTimestamp;
@property(readonly, copy, nonatomic) SNTAttributeBlock downloadAgent;
@property(readonly, copy, nonatomic) SNTAttributeBlock type;
@property(readonly, copy, nonatomic) SNTAttributeBlock pageZero;
@property(readonly, copy, nonatomic) SNTAttributeBlock codeSigned;
@property(readonly, copy, nonatomic) SNTAttributeBlock rule;
@property(readonly, copy, nonatomic) SNTAttributeBlock signingChain;

// Mapping between property string keys and SNTAttributeBlocks
@property(nonatomic) NSDictionary<NSString *, SNTAttributeBlock> *propertyMap;

@end


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
          @"    -r (--recursive): search directories recursively\n"
          @"    --json: output in json format\n"
          @"    --key: search and return this one piece of information\n"
          @"           you may specify multiple keys by repeating this flag\n"
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
          @"          santactl fileinfo /usr/bin/yes /bin/*\n"
          @"          santactl fileinfo /usr/bin -r --key Path --key SHA-256 --key Rule",
          formattedStringForKeyArray(self.fileInfoKeys),
          formattedStringForKeyArray(self.signingChainKeys)];
}

+ (NSArray<NSString *> *)fileInfoKeys {
  return @[ kPath, kSHA256, kSHA1, kBundleName, kBundleVersion, kBundleVersionStr,
            kDownloadReferrerURL, kDownloadURL, kDownloadTimestamp, kDownloadAgent,
            kType, kPageZero, kCodeSigned, kRule, kSigningChain ];
}

+ (NSArray<NSString *> *)signingChainKeys {
  return @[ kSHA256, kSHA1, kCommonName, kOrganization, kOrganizationalUnit, kValidFrom,
            kValidUntil ];
}

- (instancetype)initWithDaemonConnection:(SNTXPCConnection *)daemonConn {
  self = [super initWithDaemonConnection:daemonConn];
  if (!self) return nil;
  _recursive = NO;
  _jsonOutput = NO;

  _propertyMap = @{ kPath : self.path,
                    kSHA256 : self.sha256,
                    kSHA1 : self.sha1,
                    kBundleName : self.bundleName,
                    kBundleVersion : self.bundleVersion,
                    kBundleVersionStr : self.bundleVersionStr,
                    kDownloadReferrerURL : self.downloadReferrerURL,
                    kDownloadURL : self.downloadURL,
                    kDownloadTimestamp : self.downloadTimestamp,
                    kDownloadAgent : self.downloadAgent,
                    kType : self.type,
                    kPageZero : self.pageZero,
                    kCodeSigned : self.codeSigned,
                    kSigningChain : self.signingChain };

  return self;
}

#pragma mark property getters

- (SNTAttributeBlock)path {
  return ^id (SNTFileInfo *fileInfo) {
    return fileInfo.path;
  };
}

- (SNTAttributeBlock)sha256 {
  return ^id (SNTFileInfo *fileInfo) {
    return fileInfo.SHA256;
  };
}

- (SNTAttributeBlock)sha1 {
  return ^id (SNTFileInfo *fileInfo) {
    return fileInfo.SHA1;
  };
}

- (SNTAttributeBlock)bundleName {
  return ^id (SNTFileInfo *fileInfo) {
    return fileInfo.bundleName;
  };
}

- (SNTAttributeBlock)bundleVersion {
  return ^id (SNTFileInfo *fileInfo) {
    return fileInfo.bundleVersion;
  };
}

- (SNTAttributeBlock)bundleVersionStr {
  return ^id (SNTFileInfo *fileInfo) {
    return fileInfo.bundleShortVersionString;
  };
}

- (SNTAttributeBlock)downloadReferrerURL {
  return ^id (SNTFileInfo *fileInfo) {
    return fileInfo.quarantineRefererURL;
  };
}

- (SNTAttributeBlock)downloadURL {
  return ^id (SNTFileInfo *fileInfo) {
    return fileInfo.quarantineDataURL;
  };
}

- (SNTAttributeBlock)downloadTimestamp {
  return ^id (SNTFileInfo *fileInfo) {
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    dateFormatter.dateFormat = @"yyyy/MM/dd HH:mm:ss Z";
    return [dateFormatter stringFromDate:fileInfo.quarantineTimestamp];
  };
}

- (SNTAttributeBlock)downloadAgent {
  return ^id (SNTFileInfo *fileInfo) {
    return fileInfo.quarantineAgentBundleID;
  };
}

- (SNTAttributeBlock)type {
  return ^id (SNTFileInfo *fileInfo) {
    NSArray *archs = [fileInfo architectures];
    if (archs.count == 0) {
      return [fileInfo humanReadableFileType];
    }
    return [NSString stringWithFormat:@"%@ (%@)",
        [fileInfo humanReadableFileType], [archs componentsJoinedByString:@", "]];
  };
}

- (SNTAttributeBlock)pageZero {
  return ^id (SNTFileInfo *fileInfo) {
    if ([fileInfo isMissingPageZero]) {
      return @"__PAGEZERO segment missing/bad!";
    }
    return nil;
  };
}

- (SNTAttributeBlock)codeSigned {
  return ^id (SNTFileInfo *fileInfo) {
    NSError *error;
    MOLCodesignChecker *csc = [[MOLCodesignChecker alloc] initWithBinaryPath:fileInfo.path
                                                                       error:&error];
    if (error) {
      switch (error.code) {
        case errSecCSUnsigned:
          return @"No";
        case errSecCSSignatureFailed:
        case errSecCSStaticCodeChanged:
        case errSecCSSignatureNotVerifiable:
        case errSecCSSignatureUnsupported:
          return @"Yes, but code/signature changed/unverifiable";
        case errSecCSResourceDirectoryFailed:
        case errSecCSResourceNotSupported:
        case errSecCSResourceRulesInvalid:
        case errSecCSResourcesInvalid:
        case errSecCSResourcesNotFound:
        case errSecCSResourcesNotSealed:
          return @"Yes, but resources invalid";
        case errSecCSReqFailed:
        case errSecCSReqInvalid:
        case errSecCSReqUnsupported:
          return @"Yes, but failed requirement validation";
        case errSecCSInfoPlistFailed:
          return @"Yes, but can't validate as Info.plist is missing";
        default: {
          return [NSString stringWithFormat:@"Yes, but failed to validate (%ld)", error.code];
        }
      }
    } else if (csc.signatureFlags & kSecCodeSignatureAdhoc) {
      return @"Yes, but ad-hoc";
    } else {
      return @"Yes";
    }
  };
}

- (SNTAttributeBlock)signingChain {
  return ^id (SNTFileInfo *fileInfo) {
    NSError *error;
    MOLCodesignChecker *csc = [[MOLCodesignChecker alloc] initWithBinaryPath:fileInfo.path
                                                                       error:&error];
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    dateFormatter.dateFormat = @"yyyy/MM/dd HH:mm:ss Z";

    if (csc.certificates.count) {
      NSMutableArray *certs = [[NSMutableArray alloc] initWithCapacity:csc.certificates.count];
      [csc.certificates enumerateObjectsUsingBlock:^(MOLCertificate *c, unsigned long idx,
                                                     BOOL *stop) {
        [certs addObject:@{ kSHA256 : c.SHA256 ?: @"null",
                            kSHA1 : c.SHA1 ?: @"null",
                            kCommonName : c.commonName ?: @"null",
                            kOrganization : c.orgName ?: @"null",
                            kOrganizationalUnit : c.orgUnit ?: @"null",
                            kValidFrom : [dateFormatter stringFromDate:c.validFrom] ?: @"null",
                            kValidUntil : [dateFormatter stringFromDate:c.validUntil]
                            ?: @"null"
                            }];
      }];
      return certs;
    }
    return nil;
  };
}

# pragma mark -


- (NSString *)getDirectoryTTYColor {
  NSString *lscolors = [[NSProcessInfo processInfo] environment][@"LSCOLORS"];
  if (!lscolors || lscolors.length < 2) {
    return @"\033[1;35m";
  }
  char fg = [lscolors characterAtIndex:0];
  char bg = [lscolors characterAtIndex:1];
  char validChars[] = "abcdefghxABCDEFGHX";
  if (!strchr(validChars, fg) || !strchr(validChars, bg)) {
    return @"\033[1;35m";
  }
  NSMutableString *code = @"\033[".mutableCopy;
  if (isupper(fg)) {
    [code appendString:@"1;"];
    fg = tolower(fg);
  }
  if (fg == 'x') {
    [code appendFormat:@"0"];
  } else {
    [code appendFormat:@"%d", fg - 'a' + 30];
  }
  if (isupper(bg)) bg = tolower(bg);
  if (bg != 'x') {
    [code appendFormat:@";%d", fg - 'a' + 40];
  }
  [code appendString:@"m"];
  return code.copy;
}

// Entry point for the command.
- (void)runWithArguments:(NSArray *)arguments {
  if (!arguments.count) [self printErrorUsageAndExit:@"No arguments"];

  self.directoryColor = [self getDirectoryTTYColor];


  NSArray *filePaths = [self parseArguments:arguments];

  if (!self.outputKeyList || !self.outputKeyList.count) {
    self.outputKeyList = [[self class] fileInfoKeys];
  }

  // For consistency, JSON output is always returned as an array of file info objects, regardless of
  // how many file info objects are being outputted.  So both empty and singleton result sets are
  // still enclosed in brackets.
  if (self.jsonOutput) printf("[\n");

  NSFileManager *fm = [NSFileManager defaultManager];
  NSString *cwd = [fm currentDirectoryPath];
  for (NSString *path in filePaths) {
    NSString *fullPath = [path stringByStandardizingPath];
    if ([path characterAtIndex:0] != '/') {
      fullPath = [cwd stringByAppendingPathComponent:fullPath];
    }
    [self recurseAtPath:fullPath];
  }

  if (self.jsonOutput) printf("\n]\n"); // print closing bracket of JSON output array

  exit(0);
}

// Returns YES if we should output colored text.
- (BOOL)prettyOutput {
  return isatty(STDOUT_FILENO) && !self.jsonOutput;
}

// Print out file info for the object at the given path or, if path is a directory and the
// --recursive flag is set, print out file info for all objects in directory tree.
- (void)recurseAtPath:(NSString *)path {
  NSFileManager *fm = [NSFileManager defaultManager];
  BOOL isDir = NO, isBundle = NO;
  if (![fm fileExistsAtPath:path isDirectory:&isDir]) {
    fprintf(stderr, "File does not exist: %s\n", [path UTF8String]);
    return;
  }
  if (isDir) isBundle = [[NSWorkspace sharedWorkspace] isFilePackageAtPath:path];

  if (isDir && self.recursive) {
    NSDirectoryEnumerator<NSString *> * dirEnum = [fm enumeratorAtPath:path];
    for (NSString *file in dirEnum) {
      NSString *filepath = [path stringByAppendingPathComponent:file];
      if ([fm fileExistsAtPath:filepath isDirectory:&isDir] && isDir) {
        // Print out directory names when recursive and not outputting JSON.
        if (!self.jsonOutput) {
          if (self.prettyOutput) printf("%s", self.directoryColor.UTF8String);
          printf("%s:\n", [filepath UTF8String]);
          if (self.prettyOutput) printf("\033[0m");
        }
      } else {
        [self printInfoForFile:filepath];
      }
    }
  } else if (isDir && !isBundle) {
    fprintf(stderr, "%s is a directory.  Use the -r flag to search recursively.\n",
            [path UTF8String]);
  } else {
    [self printInfoForFile:path];
  }
}

// Getting rule information for a file requires also having a daemon connection, so we can't simply
// return a block acting on a fileInfo object to retrieve the property value.
- (NSString *)ruleForFileInfo:(SNTFileInfo *)fileInfo {
  // If we previously were unable to connect, don't try again.
  if (self.daemonUnavailable) return @"Could not communicate with daemon";
  static dispatch_once_t token;
  dispatch_once(&token, ^{ [self.daemonConn resume]; });
  __block SNTEventState state;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  NSError *error;
  MOLCodesignChecker *csc = [[MOLCodesignChecker alloc] initWithBinaryPath:fileInfo.path
                                                                     error:&error];
  [[self.daemonConn remoteObjectProxy] decisionForFilePath:fileInfo.path
                                                fileSHA256:fileInfo.SHA256
                                         certificateSHA256:csc.leafCertificate.SHA256
                                                     reply:^(SNTEventState s) {
    state = s;
    dispatch_semaphore_signal(sema);
  }];
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    self.daemonUnavailable = YES;
    return @"Could not communicate with daemon";
  } else {
    NSMutableString *output =
    (SNTEventStateAllow & state) ? @"Whitelisted".mutableCopy : @"Blacklisted".mutableCopy;
    switch (state) {
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
    if (self.prettyOutput) {
      if ((SNTEventStateAllow & state)) {
        [output insertString:@"\033[32m" atIndex:0];
        [output appendString:@"\033[0m"];
      } else if ((SNTEventStateBlock & state)) {
        [output insertString:@"\033[31m" atIndex:0];
        [output appendString:@"\033[0m"];
      } else {
        [output insertString:@"\033[33m" atIndex:0];
        [output appendString:@"\033[0m"];
      }
    }
    return output.copy;
  }
}

// Prints out the info for a single (non-directory) file.  Which info is printed is controlled
// by the keys in self.outputKeyList.
- (void)printInfoForFile:(NSString *)path {
  SNTFileInfo *fileInfo = [[SNTFileInfo alloc] initWithPath:path];
  if (!fileInfo) {
    fprintf(stderr, "Invalid or empty file: %s\n", [path UTF8String]);
    return;
  }
  if (self.jsonOutput) {
    if (self.hadPreviousEntry) printf(",\n");
    printf("%s", [self jsonStringForFileInfo:fileInfo withKeys:self.outputKeyList].UTF8String);
  } else { // print directly (so we don't have to build a big nsstring?)
    for (NSString *key in self.outputKeyList) {
      NSString *result = nil;
      if ([key isEqual:kRule]) {
        result = [self ruleForFileInfo:fileInfo];
      } else if ([key isEqual:kSigningChain]) {
        NSArray *signingChain = self.propertyMap[key](fileInfo);
        [self printSigningChain:signingChain];
      } else {
        result = self.propertyMap[key](fileInfo);
      }

      if (result) printf("%-21s: %s\n", [key UTF8String], [result UTF8String]);
    }
    printf("\n");
  }
  self.hadPreviousEntry = YES;
}

// Given a SNTFileInfo object and an array of keys, returns and nicely formatted NSString
// containing all of the key, value pairs in JSON format.
- (NSString *)jsonStringForFileInfo:(SNTFileInfo *)fileInfo withKeys:(NSArray *)keys {
  NSMutableDictionary *outputDict = [NSMutableDictionary dictionary];
  for (NSString *key in keys) {
    if ([key isEqual:kRule]) {
      outputDict[key] = [self ruleForFileInfo:fileInfo];
    } else {
      outputDict[key] = self.propertyMap[key](fileInfo);
    }
  }
  NSData *jsonData = [NSJSONSerialization dataWithJSONObject:outputDict
                                                     options:NSJSONWritingPrettyPrinted
                                                       error:NULL];
  return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}

// Parses the arguments in order to set the property variables:
//   self.recursive from --recursive or -r
//   self.json from --json
//   self.certIndex from --cert-index
//   self.outputKeyList from multiple possible --key
// and returns any non-flag args as path names in an NSArray.
- (NSArray *)parseArguments:(NSArray *)arguments {
  NSMutableArray *paths = [NSMutableArray array];
  NSMutableOrderedSet *keys = [NSMutableOrderedSet orderedSet];
  NSUInteger nargs = [arguments count];
  for (NSUInteger i = 0; i < nargs; i++) {
    NSString *arg = [arguments objectAtIndex:i];
    if ([arg caseInsensitiveCompare:@"--json"] == NSOrderedSame) {
      self.jsonOutput = YES;
    } else if ([arg caseInsensitiveCompare:@"--cert-index"] == NSOrderedSame) {
      i += 1; // advance to next argument and grab index
      if (i >= nargs || [arguments[i] hasPrefix:@"--"]) {
        [self printErrorUsageAndExit:@"\n--cert-index requires an argument"];
      }
      NSInteger index = [arguments[i] integerValue];
      if (index == 0) {
        [self printErrorUsageAndExit:
         @"\n0 is an invalid --cert-index\n  --cert-index is 1-indexed"];
      }
      self.certIndex = @(index);
    } else if ([arg caseInsensitiveCompare:@"--key"] == NSOrderedSame) {
      i += 1; // advance to next argument and grab the key
      if (i >= nargs || [arguments[i] hasPrefix:@"--"]) {
        [self printErrorUsageAndExit:@"\n--key requires an argument"];
      }
      [keys addObject:arguments[i]];
    } else if ([arg caseInsensitiveCompare:@"--recursive"] == NSOrderedSame ||
               [arg caseInsensitiveCompare:@"-r"] == NSOrderedSame) {
      self.recursive = YES;
    } else {
      [paths addObject:arg];
    }
  }

  // Do some error checking before returning to make sure that specified keys are valid.
  if (self.certIndex) {
    NSArray *validKeys = [[self class] signingChainKeys];
    for (NSString *key in keys) {
      if (![validKeys containsObject:key]) {
        [self printErrorUsageAndExit:
         [NSString stringWithFormat:@"\n\"%@\" is an invalid key when using --cert-index", key]];
      }
    }
  } else {
    NSArray *validKeys = [[self class] fileInfoKeys];
    for (NSString *key in keys) {
      if (![validKeys containsObject:key]) {
        [self printErrorUsageAndExit:
         [NSString stringWithFormat:@"\n\"%@\" is an invalid key", key]];
      }
    }
  }

  if (!paths.count) [self printErrorUsageAndExit:@"\nat least one file-path is needed"];

  self.outputKeyList = [keys array];
  return paths.copy;
}

- (void)printSigningChain:(NSArray *)signingChain {
  if (!signingChain) return;
  printf("%s:\n", kSigningChain.UTF8String);
  __block int i = 0;
  [signingChain enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
    if ([obj isEqual:[NSNull null]]) return;
    if (i++) printf("\n");
    printf("    %2lu. %-20s: %s\n", idx + 1, kSHA256.UTF8String,
           ((NSString *)obj[kSHA256]).UTF8String);
    printf("        %-20s: %s\n", kSHA1.UTF8String,
           ((NSString *)obj[kSHA1]).UTF8String);
    printf("        %-20s: %s\n", kCommonName.UTF8String,
           ((NSString *)obj[kCommonName]).UTF8String);
    printf("        %-20s: %s\n", kOrganization.UTF8String,
           ((NSString *)obj[kOrganization]).UTF8String);
    printf("        %-20s: %s\n", kOrganizationalUnit.UTF8String,
           ((NSString *)obj[kOrganizationalUnit]).UTF8String);
    printf("        %-20s: %s\n", kValidFrom.UTF8String,
           ((NSString *)obj[kValidFrom]).UTF8String);
    printf("        %-20s: %s\n", kValidUntil.UTF8String,
           ((NSString *)obj[kValidUntil]).UTF8String);
  }];
}

@end
