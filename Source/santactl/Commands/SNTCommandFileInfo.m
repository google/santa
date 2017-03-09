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

BOOL PrettyOutput() {
  static int tty = 0;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    tty = isatty(STDOUT_FILENO);
  });
  return (tty && !json);
}

#pragma mark SNTCommandFileInfo

@interface SNTCommandFileInfo : NSObject<SNTCommand>

@property(nonatomic) SNTXPCConnection *daemonConn;
@property(nonatomic) SNTFileInfo *fileInfo;
@property(nonatomic) MOLCodesignChecker *csc;

// file path used for object initialization
@property(readonly, nonatomic) NSString *filePath;

// Block type to be used with propertyMap values
typedef id (^SNTAttributeBlock)(SNTCommandFileInfo *);

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
@property(nonatomic) NSMutableDictionary<NSString *, SNTAttributeBlock> *propertyMap;

// Common Date Formatter
@property(nonatomic) NSDateFormatter *dateFormatter;

// Block Helpers
- (NSString *)humanReadableFileType:(SNTFileInfo *)fi;

@end

@implementation SNTCommandFileInfo

REGISTER_COMMAND_NAME(@"fileinfo")

- (instancetype)initWithFilePath:(NSString *)filePath
                daemonConnection:(SNTXPCConnection *)daemonConn {
  self = [super init];
  if (self) {
    _filePath = filePath;
    _daemonConn = daemonConn;
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
                      kSigningChain : self.signingChain }.mutableCopy;
  }
  return self;
}

#pragma mark property getters

- (SNTFileInfo *)fileInfo {
  if (!_fileInfo) {
    _fileInfo = [[SNTFileInfo alloc] initWithPath:self.filePath];
    if (!_fileInfo) {
      fprintf(stderr, "\rInvalid or empty file: %s\n", self.filePath.UTF8String);
    }
  }
  return _fileInfo;
}

- (SNTAttributeBlock)path {
  return ^id (SNTCommandFileInfo *fi) {
    return fi.fileInfo.path;
  };
}

- (SNTAttributeBlock)sha256 {
  return ^id (SNTCommandFileInfo *fi) {
    return fi.fileInfo.SHA256;
  };
}

- (SNTAttributeBlock)sha1 {
  return ^id (SNTCommandFileInfo *fi) {
    return fi.fileInfo.SHA1;
  };
}

- (SNTAttributeBlock)bundleName {
  return ^id (SNTCommandFileInfo *fi) {
    return fi.fileInfo.bundleName;
  };
}

- (SNTAttributeBlock)bundleVersion {
  return ^id (SNTCommandFileInfo *fi) {
    return fi.fileInfo.bundleVersion;
  };
}

- (SNTAttributeBlock)bundleVersionStr {
  return ^id (SNTCommandFileInfo *fi) {
    return fi.fileInfo.bundleShortVersionString;
  };
}

- (SNTAttributeBlock)downloadReferrerURL {
  return ^id (SNTCommandFileInfo *fi) {
    return fi.fileInfo.quarantineRefererURL;
  };
}

- (SNTAttributeBlock)downloadURL {
  return ^id (SNTCommandFileInfo *fi) {
    return fi.fileInfo.quarantineDataURL;
  };
}

- (SNTAttributeBlock)downloadTimestamp {
  return ^id (SNTCommandFileInfo *fi) {
    return [fi.dateFormatter stringFromDate:fi.fileInfo.quarantineTimestamp];
  };
}

- (SNTAttributeBlock)downloadAgent {
  return ^id (SNTCommandFileInfo *fi) {
    return fi.fileInfo.quarantineAgentBundleID;
  };
}

- (SNTAttributeBlock)type {
  return ^id (SNTCommandFileInfo *fi) {
    NSArray *archs = [fi.fileInfo architectures];
    if (archs.count == 0) {
      return [fi humanReadableFileType:fi.fileInfo];
    }
    return [NSString stringWithFormat:@"%@ (%@)",
               [fi humanReadableFileType:fi.fileInfo], [archs componentsJoinedByString:@", "]];
  };
}

- (SNTAttributeBlock)pageZero {
  return ^id (SNTCommandFileInfo *fi) {
    if ([fi.fileInfo isMissingPageZero]) {
      return @"__PAGEZERO segment missing/bad!";
    }
    return nil;
  };
}

- (SNTAttributeBlock)codeSigned {
  return ^id (SNTCommandFileInfo *fi) {
    NSError *error;
    fi.csc = [[MOLCodesignChecker alloc] initWithBinaryPath:fi.filePath error:&error];
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
    } else if (fi.csc.signatureFlags & kSecCodeSignatureAdhoc) {
      return @"Yes, but ad-hoc";
    } else {
      return @"Yes";
    }
  };
}

- (SNTAttributeBlock)rule {
  return ^id (SNTCommandFileInfo *fi) {
    __block SNTEventState s;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
      [fi.daemonConn resume];
    });
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    if (!fi.csc) {
      NSError *error;
      fi.csc = [[MOLCodesignChecker alloc] initWithBinaryPath:fi.path(fi) error:&error];
    }
    [[fi.daemonConn remoteObjectProxy] decisionForFilePath:fi.path(fi)
                                                fileSHA256:fi.propertyMap[kSHA256](fi)
                                        signingCertificate:fi.csc.leafCertificate
                                                     reply:^(SNTEventState state) {
      if (state) s = state;
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
      if (PrettyOutput()) {
        if ((SNTEventStateAllow & s)) {
          [output insertString:@"\033[32m" atIndex:0];
          [output appendString:@"\033[0m"];
        } else if ((SNTEventStateBlock & s)) {
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
  return ^id (SNTCommandFileInfo *fi) {
    if (!fi.csc) {
      NSError *error;
      fi.csc = [[MOLCodesignChecker alloc] initWithBinaryPath:fi.filePath error:&error];
    }
    if (fi.csc.certificates.count) {
      NSMutableArray *certs = [[NSMutableArray alloc] initWithCapacity:fi.csc.certificates.count];
      [fi.csc.certificates enumerateObjectsUsingBlock:^(MOLCertificate *c, unsigned long idx,
                                                        BOOL *stop) {
        [certs addObject:@{ kSHA256 : c.SHA256 ?: @"null",
                            kSHA1 : c.SHA1 ?: @"null",
                            kCommonName : c.commonName ?: @"null",
                            kOrganization : c.orgName ?: @"null",
                            kOrganizationalUnit : c.orgUnit ?: @"null",
                            kValidFrom : [fi.dateFormatter stringFromDate:c.validFrom] ?: @"null",
                            kValidUntil : [fi.dateFormatter stringFromDate:c.validUntil]
                                ?: @"null"
                          }];
      }];
      return certs;
    }
    return nil;
  };
}

- (NSString *)humanReadableFileType:(SNTFileInfo *)fi {
  if ([fi isScript]) return @"Script";
  if ([fi isExecutable]) return @"Executable";
  if ([fi isDylib]) return @"Dynamic Library";
  if ([fi isBundle]) return @"Bundle/Plugin";
  if ([fi isKext]) return @"Kernel Extension";
  if ([fi isXARArchive]) return @"XAR Archive";
  if ([fi isDMG]) return @"Disk Image";
  return @"Unknown";
}

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
             [self printKeyArray:[self fileInfoKeys]],
             [self printKeyArray:[self signingChainKeys]]];
}

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  if (!arguments.count) [self printErrorUsageAndExit:@"No arguments"];

  NSString *key;
  NSNumber *certIndex;
  NSArray *filePaths;

  [self parseArguments:arguments
                forKey:&key
             certIndex:&certIndex
            jsonOutput:&json
             filePaths:&filePaths];

  // Only access outputHashes from the outputHashesQueue
  __block NSMutableArray *outputHashes = [[NSMutableArray alloc] initWithCapacity:filePaths.count];
  dispatch_group_t outputHashesGroup = dispatch_group_create();
  dispatch_queue_t outputHashesQueue =
      dispatch_queue_create("com.google.santa.outputhashes", DISPATCH_QUEUE_SERIAL);

  __block NSOperationQueue *hashQueue = [[NSOperationQueue alloc] init];
  hashQueue.maxConcurrentOperationCount = 15;

  __block NSUInteger hashed = 0;

  [filePaths enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
    NSBlockOperation *hashOperation = [NSBlockOperation blockOperationWithBlock:^{
      if (PrettyOutput()) printf("\rCalculating %lu/%lu", ++hashed, filePaths.count);

      SNTCommandFileInfo *fi = [[self alloc] initWithFilePath:obj daemonConnection:daemonConn];
      if (!fi.fileInfo) return;

      __block NSMutableDictionary *outputHash = [[NSMutableDictionary alloc] init];

      if (key && !certIndex) {
        SNTAttributeBlock block = fi.propertyMap[key];
        outputHash[key] = block(fi);
      } else if (certIndex) {
        NSArray *signingChain = fi.signingChain(fi);
        if (key) {
          if ([certIndex isEqual:@(-1)]) {
            outputHash[key] = signingChain.lastObject[key];
          } else {
            if (certIndex.unsignedIntegerValue - 1 < signingChain.count) {
              outputHash[key] = signingChain[certIndex.unsignedIntegerValue - 1][key];
            }
          }
        } else {
          if ([certIndex isEqual:@(-1)]) {
            outputHash[kSigningChain] = @[ signingChain.lastObject ?: @{} ];
          } else {
            NSMutableArray *indexedCert = [NSMutableArray arrayWithCapacity:signingChain.count];
            [signingChain enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
              if (certIndex.unsignedIntegerValue - 1 == idx) {
                [indexedCert addObject:obj];
              } else {
                [indexedCert addObject:[NSNull null]];
              }
            }];
            if (indexedCert.count) outputHash[kSigningChain] = indexedCert;
          }
        }
      } else {
        NSString *sha1, *sha256;
        [fi.fileInfo hashSHA1:&sha1 SHA256:&sha256];
        fi.propertyMap[kSHA1] = ^id (SNTCommandFileInfo *fi) { return sha1; };
        fi.propertyMap[kSHA256] = ^id (SNTCommandFileInfo *fi) { return sha256; };
        [fi.propertyMap enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
          SNTAttributeBlock block = obj;
          outputHash[key] = block(fi);
        }];
      }
      if (outputHash.count) {
        dispatch_group_async(outputHashesGroup, outputHashesQueue, ^{
          [outputHashes addObject:outputHash];
        });
      }
    }];
    
    hashOperation.qualityOfService = NSQualityOfServiceUserInitiated;
    [hashQueue addOperation:hashOperation];
  }];

  // Wait for all the calculating threads to finish
  [hashQueue waitUntilAllOperationsAreFinished];

  // Clear the "Calculating ..." indicator if present
  if (PrettyOutput()) printf("\33[2K\r");

  // Wait for all the writes to the outputHashes to finish
  dispatch_group_wait(outputHashesGroup, DISPATCH_TIME_FOREVER);

  if (outputHashes.count) [self printOutputHashes:outputHashes];
  exit(0);
}

#pragma mark FileInfo helper methods

+ (NSArray *)fileInfoKeys {
  return @[ kPath, kSHA256, kSHA1, kBundleName, kBundleVersion, kBundleVersionStr,
            kDownloadReferrerURL, kDownloadURL, kDownloadTimestamp, kDownloadAgent,
            kType, kPageZero, kCodeSigned, kRule, kSigningChain ];
}

+ (NSArray *)signingChainKeys {
  return @[ kSHA256, kSHA1, kCommonName, kOrganization, kOrganizationalUnit, kValidFrom,
            kValidUntil ];
}

+ (NSString *)printKeyArray:(NSArray *)array {
  __block NSMutableString *string = [[NSMutableString alloc] init];
  [array enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
    [string appendString:[NSString stringWithFormat:@"                       \"%@\"\n", obj]];
  }];
  return string;
}

+ (void)printErrorUsageAndExit:(NSString *)error {
  printf("%s\n\n", [error UTF8String]);
  printf("%s\n", [[self longHelpText] UTF8String]);
  exit(1);
}

+ (void)parseArguments:(NSArray *)args
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
  if (*key && !*certIndex && ![self.fileInfoKeys containsObject:*key]) {
    [self printErrorUsageAndExit:
        [NSString stringWithFormat:@"\n\"%@\" is an invalid key", *key]];
  } else if (*key && *certIndex && ![self.signingChainKeys containsObject:*key]) {
    [self printErrorUsageAndExit:
        [NSString stringWithFormat:@"\n\"%@\" is an invalid key when using --cert-index", *key]];
  } else if ([@(0) isEqual:*certIndex]) {
    [self printErrorUsageAndExit:@"\n0 is an invalid --cert-index\n  --cert-index is 1 indexed"];
  }
  if (!paths.count) [self printErrorUsageAndExit:@"\nat least one file-path is needed"];
  *filePaths = paths.copy;
}

+ (void)printOutputHashes:(NSArray *)outputHashes {
  if (json) {
    id object = (outputHashes.count > 1) ? outputHashes : outputHashes.firstObject;
    if (!object) return;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:object
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:NULL];
    printf("%s\n", [[NSString alloc] initWithData:jsonData
                                         encoding:NSUTF8StringEncoding].UTF8String);
    return;
  }

  [outputHashes enumerateObjectsUsingBlock:^(id outputHash, NSUInteger idx, BOOL *stop) {
    if ([outputHash count] == 1) {
      return [self printValueFromOutputHash:outputHash];
    }
    [self.fileInfoKeys enumerateObjectsUsingBlock:^(id key, NSUInteger idx, BOOL *stop) {
      [self printValueForKey:key fromOutputHash:outputHash];
    }];
    printf("\n");
  }];
}

+ (void)printValueForKey:(NSString *)key fromOutputHash:(NSDictionary *)outputHash {
  id value = outputHash[key];
  if (!value) return;
  if ([key isEqualToString:kSigningChain]) {
    return [self printSigningChain:value];
  }
  printf("%-21s: %s\n", [key UTF8String], [value UTF8String]);
}

+ (void)printValueFromOutputHash:(NSDictionary *)outputHash {
  if ([[[outputHash allKeys] firstObject] isEqualToString:kSigningChain]) {
    return [self printSigningChain:[[outputHash allValues] firstObject]];
  }
  printf("%s\n", [[[outputHash allValues] firstObject] UTF8String]);
}

+ (void)printSigningChain:(NSArray *)signingChain {
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
