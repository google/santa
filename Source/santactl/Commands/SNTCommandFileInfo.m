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

#import <objc/runtime.h>
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

// Message displayed when daemon communication fails
static NSString *const kCommunicationErrorMsg = @"Could not communicate with daemon";

// Used by longHelpText to display a list of valid keys passed in as an array.
NSString *formattedStringForKeyArray(NSArray<NSString *> *array) {
  NSMutableString *result = [[NSMutableString alloc] init];
  for (NSString *key in array) {
    [result appendString:[NSString stringWithFormat:@"                       \"%@\"\n", key]];
  }
  return result;
}

@interface SNTCommandFileInfo : SNTCommand<SNTCommandProtocol>

// Properties set from commandline flags
@property(nonatomic) BOOL recursive;
@property(nonatomic) BOOL jsonOutput;
@property(nonatomic) int certIndex;  // 0 means no cert-index specified
@property(nonatomic, copy) NSArray<NSString *> *outputKeyList;
@property(nonatomic, copy) NSDictionary<NSString *, NSRegularExpression *> *outputFilters;

// Flag indicating when to use TTY colors
@property(readonly, nonatomic) BOOL prettyOutput;

// Flag needed when printing JSON for multiple files to get commas right
@property(nonatomic) BOOL jsonPreviousEntry;

// Flag used to avoid multiple attempts to connect to daemon
@property(nonatomic) BOOL daemonUnavailable;

// Common date formatter
@property(nonatomic) NSDateFormatter *dateFormatter;

// Maximum length of output key name, used for formatting
@property(nonatomic) NSUInteger maxKeyWidth;

// Valid key lists
@property(readonly, nonatomic) NSArray<NSString *> *fileInfoKeys;
@property(readonly, nonatomic) NSArray<NSString *> *signingChainKeys;

// Block type to be used with propertyMap values.  The first SNTCommandFileInfo parameter
// is really required only for the the rule property getter which needs access to the daemon
// connection, but downloadTimestamp & signingChain also use it for a shared date formatter.
typedef id (^SNTAttributeBlock)(SNTCommandFileInfo *, SNTFileInfo *);

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

// Serial queue and dispatch group used for printing output
@property(nonatomic) dispatch_queue_t printQueue;
@property(nonatomic) dispatch_group_t printGroup;

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
          @"    --recursive (-r): Search directories recursively.\n"
          @"    --json: Output in JSON format.\n"
          @"    --key: Search and return this one piece of information.\n"
          @"           You may specify multiple keys by repeating this flag.\n"
          @"           Valid Keys:\n"
          @"%@\n"
          @"           Valid keys when using --cert-index:\n"
          @"%@\n"
          @"    --cert-index: Supply an integer corresponding to a certificate of the\n"
          @"                  signing chain to show info only for that certificate.\n"
          @"                     1 for the leaf certificate\n"
          @"                    -1 for the root certificate\n"
          @"                     2 and up for the intermediates / root\n"
          @"\n"
          @"    --filter: Use predicates of the form 'key=regex' to filter out which files\n"
          @"              are displayed. Valid keys are the same as for --key. Value is a\n"
          @"              case-insensitive regular expression which must match anywhere in\n"
          @"              the keyed property value for the file's info to be displayed.\n"
          @"              You may specify multiple filters by repeating this flag.\n"
          @"\n"
          @"Examples: santactl fileinfo --cert-index 1 --key SHA-256 --json /usr/bin/yes\n"
          @"          santactl fileinfo --key SHA-256 --json /usr/bin/yes\n"
          @"          santactl fileinfo /usr/bin/yes /bin/*\n"
          @"          santactl fileinfo /usr/bin -r --key Path --key SHA-256 --key Rule\n"
          @"          santactl fileinfo /usr/bin/* --filter Type=Script --filter Path=zip",
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
  if (self) {
    _dateFormatter = [[NSDateFormatter alloc] init];
    _dateFormatter.dateFormat = @"yyyy/MM/dd HH:mm:ss Z";

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
                      kRule : self.rule,
                      kSigningChain : self.signingChain };

    _printQueue = dispatch_queue_create("com.google.santactl.print_queue", DISPATCH_QUEUE_SERIAL);
  }
  return self;
}

#pragma mark property getters

- (SNTAttributeBlock)path {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.path;
  };
}

- (SNTAttributeBlock)sha256 {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.SHA256;
  };
}

- (SNTAttributeBlock)sha1 {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.SHA1;
  };
}

- (SNTAttributeBlock)bundleName {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.bundleName;
  };
}

- (SNTAttributeBlock)bundleVersion {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.bundleVersion;
  };
}

- (SNTAttributeBlock)bundleVersionStr {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.bundleShortVersionString;
  };
}

- (SNTAttributeBlock)downloadReferrerURL {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.quarantineRefererURL;
  };
}

- (SNTAttributeBlock)downloadURL {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.quarantineDataURL;
  };
}

- (SNTAttributeBlock)downloadTimestamp {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return [cmd.dateFormatter stringFromDate:fileInfo.quarantineTimestamp];
  };
}

- (SNTAttributeBlock)downloadAgent {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.quarantineAgentBundleID;
  };
}

- (SNTAttributeBlock)type {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    NSArray *archs = [fileInfo architectures];
    if (archs.count == 0) {
      return [fileInfo humanReadableFileType];
    }
    return [NSString stringWithFormat:@"%@ (%@)",
        [fileInfo humanReadableFileType], [archs componentsJoinedByString:@", "]];
  };
}

- (SNTAttributeBlock)pageZero {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    if ([fileInfo isMissingPageZero]) {
      return @"__PAGEZERO segment missing/bad!";
    }
    return nil;
  };
}

- (SNTAttributeBlock)codeSigned {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    NSError *error;
    MOLCodesignChecker *csc = [fileInfo codesignCheckerWithError:&error];
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

- (SNTAttributeBlock)rule {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    // If we previously were unable to connect, don't try again.
    if (cmd.daemonUnavailable) return kCommunicationErrorMsg;
    static dispatch_once_t token;
    dispatch_once(&token, ^{ [cmd.daemonConn resume]; });
    __block SNTEventState state;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    NSError *err;
    MOLCodesignChecker *csc = [fileInfo codesignCheckerWithError:&err];
    [[cmd.daemonConn remoteObjectProxy] decisionForFilePath:fileInfo.path
                                                 fileSHA256:fileInfo.SHA256
                                          certificateSHA256:err ? nil : csc.leafCertificate.SHA256
                                                      reply:^(SNTEventState s) {
      state = s;
      dispatch_semaphore_signal(sema);
    }];
    if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
      cmd.daemonUnavailable = YES;
      return kCommunicationErrorMsg;
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
      if (cmd.prettyOutput) {
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
  };
}

- (SNTAttributeBlock)signingChain {
  return ^id (SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    MOLCodesignChecker *csc = [fileInfo codesignCheckerWithError:NULL];
    if (!csc.certificates.count) return nil;
    NSMutableArray *certs = [[NSMutableArray alloc] initWithCapacity:csc.certificates.count];
    for (MOLCertificate *c in csc.certificates) {
      [certs addObject:@{
        kSHA256 : c.SHA256 ?: @"null",
        kSHA1 : c.SHA1 ?: @"null",
        kCommonName : c.commonName ?: @"null",
        kOrganization : c.orgName ?: @"null",
        kOrganizationalUnit : c.orgUnit ?: @"null",
        kValidFrom : [cmd.dateFormatter stringFromDate:c.validFrom] ?: @"null",
        kValidUntil : [cmd.dateFormatter stringFromDate:c.validUntil] ?: @"null"
      }];
    }
    return certs;
  };
}

# pragma mark -

// Entry point for the command.
- (void)runWithArguments:(NSArray *)arguments {
  if (!arguments.count) [self printErrorUsageAndExit:@"No arguments"];

  NSArray *filePaths = [self parseArguments:arguments];

  if (!self.outputKeyList || !self.outputKeyList.count) {
    if (self.certIndex) {
      self.outputKeyList = [[self class] signingChainKeys];
    } else {
      self.outputKeyList = [[self class] fileInfoKeys];
    }
  }
  // Figure out max field width from list of keys
  self.maxKeyWidth = 0;
  for (NSString *key in self.outputKeyList) {
    if (key.length > self.maxKeyWidth) self.maxKeyWidth = key.length;
  }

  // For consistency, JSON output is always returned as an array of file info objects, regardless of
  // how many file info objects are being outputted.  So both empty and singleton result sets are
  // still enclosed in brackets.
  if (self.jsonOutput) printf("[\n");

  NSFileManager *fm = [NSFileManager defaultManager];
  NSString *cwd = [fm currentDirectoryPath];

  // Dispatch group for tasks printing to stdout.
  self.printGroup = dispatch_group_create();

  [filePaths enumerateObjectsWithOptions:NSEnumerationConcurrent
                              usingBlock:^(NSString *path, NSUInteger idx, BOOL *stop) {
    NSString *fullPath = [path stringByStandardizingPath];
    if (path.length && [path characterAtIndex:0] != '/') {
      fullPath = [cwd stringByAppendingPathComponent:fullPath];
    }
    [self recurseAtPath:fullPath];
  }];

  // Wait for all tasks in print queue to complete.
  dispatch_group_wait(self.printGroup, DISPATCH_TIME_FOREVER);

  if (self.jsonOutput) printf("\n]\n");  // print closing bracket of JSON output array

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
    dispatch_group_async(self.printGroup, self.printQueue, ^{
      fprintf(stderr, "File does not exist: %s\n", [path UTF8String]);
    });
    return;
  }

  if (isDir) {
    NSBundle *bundle = [NSBundle bundleWithPath:path];
    isBundle = bundle && [bundle bundleIdentifier];
  }

  NSOperationQueue *operationQueue = [[NSOperationQueue alloc] init];
  operationQueue.qualityOfService = NSQualityOfServiceUserInitiated;

  if (isDir && self.recursive) {
    NSDirectoryEnumerator *dirEnum = [fm enumeratorAtPath:path];
    NSString *file = [dirEnum nextObject];
    while (file) {
      @autoreleasepool {
        NSString *filepath = [path stringByAppendingPathComponent:file];
        BOOL exists = [fm fileExistsAtPath:filepath isDirectory:&isDir];
        if (!(exists && isDir)) {  // don't display anything for a directory path
          [operationQueue addOperationWithBlock:^{
            [self printInfoForFile:filepath];
          }];
        }
        file = [dirEnum nextObject];
      }
    }
  } else if (isDir && !isBundle) {
    dispatch_group_async(self.printGroup, self.printQueue, ^{
      fprintf(stderr, "%s is a directory.  Use the -r flag to search recursively.\n",
          [path UTF8String]);
    });
  } else {
    [operationQueue addOperationWithBlock:^{
      [self printInfoForFile:path];
    }];
  }

  [operationQueue waitUntilAllOperationsAreFinished];
}

// Prints out the info for a single (non-directory) file.  Which info is printed is controlled
// by the keys in self.outputKeyList.
- (void)printInfoForFile:(NSString *)path {
  SNTFileInfo *fileInfo = [[SNTFileInfo alloc] initWithPath:path];
  if (!fileInfo) {
    dispatch_group_async(self.printGroup, self.printQueue, ^{
      fprintf(stderr, "Invalid or empty file: %s\n", [path UTF8String]);
    });
    return;
  }

  // First build up a dictionary containing all the information we want to print out
  NSMutableDictionary *outputDict = [NSMutableDictionary dictionary];
  if (self.certIndex) {
    // --cert-index flag implicitly means that we want only the signing chain.  So we find the
    // specified certificate in the signing chain, then print out values for all keys in cert.
    NSArray *signingChain = self.propertyMap[kSigningChain](self, fileInfo);
    if (!signingChain || !signingChain.count) return;  // check signing chain isn't empty
    int index = (self.certIndex == -1) ? (int)signingChain.count - 1 : self.certIndex - 1;
    if (index < 0 || index >= (int)signingChain.count) return;  // check that index is valid
    NSDictionary *cert = signingChain[index];

    // Check if we should skip over this item based on outputFilters.
    for (NSString *key in self.outputFilters) {
      NSString *value = cert[key];
      NSRegularExpression *regex = self.outputFilters[key];
      if (![regex firstMatchInString:value options:0 range:NSMakeRange(0, value.length)]) return;
    }

    // Filter out the info we want now, in case JSON output
    for (NSString *key in self.outputKeyList) {
      outputDict[key] = cert[key];
    }
  } else {
    // Check if we should skip over this item based on outputFilters.  We do this before collecting
    // output info because there's a chance that we can bail out early if a filter doesn't match.
    // However we also don't want to recompute info, so we save any values that we plan to show.
    for (NSString *key in self.outputFilters) {
      NSString *value = self.propertyMap[key](self, fileInfo);
      NSRegularExpression *regex = self.outputFilters[key];
      if (![regex firstMatchInString:value options:0 range:NSMakeRange(0, value.length)]) return;
      // If this is a value we want to show, store it in the output dictionary.
      // This does a linear search on an array, but it's a small array.
      if ([self.outputKeyList containsObject:key]) {
        outputDict[key] = value;
      }
    }

    // Then fill the outputDict with the rest of the missing values.
    for (NSString *key in self.outputKeyList) {
      if (outputDict[key]) continue;  // ignore keys that we've already set due to a filter
      outputDict[key] = self.propertyMap[key](self, fileInfo);
    }
  }

  // If there's nothing in the outputDict, then don't need to print anything.
  if (!outputDict.count) return;

  // Then display the information in the dictionary.  How we display it depends on
  // a) do we want JSON output?
  // b) is there only one key?
  // c) are we displaying a cert?
  BOOL singleKey = (self.outputKeyList.count == 1 &&
                    ![self.outputKeyList.firstObject isEqual:kSigningChain]);
  NSMutableString *output = [NSMutableString string];
  if (self.jsonOutput) {
    [output appendString:[self jsonStringForDictionary:outputDict]];
  } else {
    for (NSString *key in self.outputKeyList) {
      if (![outputDict objectForKey:key]) continue;
      if ([key isEqual:kSigningChain]) {
        [output appendString:[self stringForSigningChain:outputDict[key]]];
      } else {
        if (singleKey) {
          [output appendFormat:@"%@\n", outputDict[key]];
        } else {
          [output appendFormat:@"%-*s: %@\n",
              (int)self.maxKeyWidth, key.UTF8String, outputDict[key]];
        }
      }
    }
    if (!singleKey) [output appendString:@"\n"];
  }

  dispatch_group_async(self.printGroup, self.printQueue, ^{
    if (self.jsonOutput) {  // print commas between JSON entries
      if (self.jsonPreviousEntry) printf(",\n");
      self.jsonPreviousEntry = YES;
    }
    printf("%s", output.UTF8String);
  });
}

// Parses the arguments in order to set the property variables:
//   self.recursive from --recursive or -r
//   self.json from --json
//   self.certIndex from --cert-index argument
//   self.outputKeyList from multiple possible --key arguments
//   self.outputFilters from multiple possible --filter arguments
// and returns any non-flag args as path names in an NSArray.
- (NSArray *)parseArguments:(NSArray<NSString *> *)arguments {
  NSMutableArray *paths = [NSMutableArray array];
  NSMutableOrderedSet *keys = [NSMutableOrderedSet orderedSet];
  NSMutableDictionary *filters = [NSMutableDictionary dictionary];
  NSUInteger nargs = [arguments count];
  for (NSUInteger i = 0; i < nargs; i++) {
    NSString *arg = [arguments objectAtIndex:i];
    if ([arg caseInsensitiveCompare:@"--json"] == NSOrderedSame) {
      self.jsonOutput = YES;
    } else if ([arg caseInsensitiveCompare:@"--cert-index"] == NSOrderedSame) {
      i += 1;  // advance to next argument and grab index
      if (i >= nargs || [arguments[i] hasPrefix:@"--"]) {
        [self printErrorUsageAndExit:@"\n--cert-index requires an argument"];
      }
      int index = 0;
      NSScanner *scanner = [NSScanner scannerWithString:arguments[i]];
      if (![scanner scanInt:&index] || !scanner.atEnd || index == 0 || index < -1) {
        [self printErrorUsageAndExit:[NSString stringWithFormat:
            @"\n\"%@\" is an invalid argument for --cert-index\n"
            @"  --cert-index argument must be one of -1, 1, 2, 3, ...", arguments[i]]];
      }
      self.certIndex = index;
    } else if ([arg caseInsensitiveCompare:@"--key"] == NSOrderedSame) {
      i += 1;  // advance to next argument and grab the key
      if (i >= nargs || [arguments[i] hasPrefix:@"--"]) {
        [self printErrorUsageAndExit:@"\n--key requires an argument"];
      }
      [keys addObject:arguments[i]];
    } else if ([arg caseInsensitiveCompare:@"--filter"] == NSOrderedSame) {
      i += 1;  // advance to next argument and grab the filter predicate
      if (i >= nargs || [arguments[i] hasPrefix:@"--"]) {
        [self printErrorUsageAndExit:@"\n--filter requires an argument"];
      }
      // Check that filter predicate has the format "key=regex".
      NSRange range = [arguments[i] rangeOfString:@"="];
      if (range.location == NSNotFound || range.location == 0 ||
          range.location == arguments[i].length - 1) {
        [self printErrorUsageAndExit:[NSString stringWithFormat:
            @"\n\"%@\" is an invalid filter predicate.\n"
            @"Filter predicates must be of the form key=regex"
            @" (with no spaces around \"=\")", arguments[i]]];
      }
      NSString *key = [arguments[i] substringToIndex:range.location];
      NSString *rhs = [arguments[i] substringFromIndex:range.location+1];
      // Convert right-hand side of '=' into a regular expression object.
      NSError *error;
      NSRegularExpression *regex =
          [NSRegularExpression regularExpressionWithPattern:rhs
                                                    options:NSRegularExpressionCaseInsensitive
                                                      error:&error];
      if (error) {
        [self printErrorUsageAndExit:[NSString stringWithFormat:
            @"\n\"%@\" is an invalid regular expression in filter argument.\n", rhs]];
      }
      filters[key] = regex;
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
    for (NSString *key in filters) {
      if (![validKeys containsObject:key]) {
        [self printErrorUsageAndExit:[NSString stringWithFormat:
            @"\n\"%@\" is an invalid filter key when using --cert-index", key]];
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
    for (NSString *key in filters) {
      if (![validKeys containsObject:key] || [key isEqualToString:kSigningChain]) {
        [self printErrorUsageAndExit:
            [NSString stringWithFormat:@"\n\"%@\" is an invalid filter key", key]];
      }
    }
  }

  if (!paths.count) [self printErrorUsageAndExit:@"\nat least one file-path is needed"];

  self.outputKeyList = [keys array];
  self.outputFilters = [filters copy];
  return paths.copy;
}

- (NSString *)jsonStringForDictionary:(NSDictionary *)dict {
  NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dict
                                                     options:NSJSONWritingPrettyPrinted
                                                       error:NULL];
  return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}

- (NSString *)stringForSigningChain:(NSArray *)signingChain {
  if (!signingChain) return @"";
  NSMutableString *result = [NSMutableString string];
  [result appendFormat:@"%@:\n", kSigningChain];
  int i = 1;
  NSArray<NSString *> *certKeys = [[self class] signingChainKeys];
  for (NSDictionary *cert in signingChain) {
    if ([cert isEqual:[NSNull null]]) continue;
    if (i > 1) [result appendFormat:@"\n"];
    [result appendString:[self stringForCertificate:cert withKeys:certKeys index:i]];
    i += 1;
  }
  return result.copy;
}

- (NSString *)stringForCertificate:(NSDictionary *)cert withKeys:(NSArray *)keys index:(int)index {
  if (!cert) return @"";
  NSMutableString *result = [NSMutableString string];
  BOOL firstKey = YES;
  for (NSString *key in keys) {
    if (firstKey) {
      [result appendFormat:@"    %2d. %-20s: %@\n", index, key.UTF8String, cert[key]];
      firstKey = NO;
    } else {
      [result appendFormat:@"        %-20s: %@\n", key.UTF8String, cert[key]];
    }
  }
  return result.copy;
}

@end
