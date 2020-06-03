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


#import <Foundation/Foundation.h>
#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>
#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDropRootPrivs.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandRule : SNTCommand<SNTCommandProtocol>
@end

@implementation SNTCommandRule

REGISTER_COMMAND_NAME(@"rule")

+ (BOOL)requiresRoot {
  return YES;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Manually add/remove/check rules.";
}

+ (NSString *)longHelpText {
  return (@"Usage: santactl rule [options]\n"
          @"  One of:\n"
          @"    --allow: add to allow\n"
          @"    --block: add to block\n"
          @"    --silent-block: add to silent block\n"
          @"    --compiler: allow and mark as a compiler\n"
          @"    --remove: remove existing rule\n"
          @"    --check: check for an existing rule\n"
          @"\n"
          @"  One of:\n"
          @"    --path {path}: path of binary/bundle to add/remove.\n"
          @"                   Will add the hash of the file currently at that path.\n"
          @"                   Does not work with --check. Use the fileinfo verb to check.\n"
          @"                   the rule state of a file.\n"
          @"    --sha256 {sha256}: hash to add/remove/check\n"
          @"\n"
          @"  Optionally:\n"
          @"    --certificate: add or check a certificate sha256 rule instead of binary\n"
#ifdef DEBUG
          @"    --force: allow manual changes even when SyncBaseUrl is set\n"
#endif
          @"    --message {message}: custom message\n");
}

- (void)runWithArguments:(NSArray *)arguments {
  SNTConfigurator *config = [SNTConfigurator configurator];
  // DEBUG builds add a --force flag to allow manually adding/removing rules during testing.
#ifdef DEBUG
  if ([config syncBaseURL] &&
      ![arguments containsObject:@"--check"] &&
      ![arguments containsObject:@"--force"]) {
#else
  if ([config syncBaseURL] && ![arguments containsObject:@"--check"]) {
#endif
    printf("SyncBaseURL is set, rules are managed centrally.\n");
    exit(1);
  }

  SNTRule *newRule = [[SNTRule alloc] init];
  newRule.state = SNTRuleStateUnknown;
  newRule.type = SNTRuleTypeBinary;

  NSString *path;
  BOOL check = NO;

  // Parse arguments
  for (NSUInteger i = 0; i < arguments.count; ++i) {
    NSString *arg = arguments[i];

    if ([arg caseInsensitiveCompare:@"--allowlist"] == NSOrderedSame ||
        [arg caseInsensitiveCompare:@"--whitelist"] == NSOrderedSame) {
      newRule.state = SNTRuleStateAllow;
    } else if ([arg caseInsensitiveCompare:@"--blocklist"] == NSOrderedSame ||
               [arg caseInsensitiveCompare:@"--blacklist"] == NSOrderedSame) {
      newRule.state = SNTRuleStateBlock;
    } else if ([arg caseInsensitiveCompare:@"--silent-blocklist"] == NSOrderedSame ||
               [arg caseInsensitiveCompare:@"--silent-blacklist"] == NSOrderedSame) {
      newRule.state = SNTRuleStateSilentBlock;
    } else if ([arg caseInsensitiveCompare:@"--compiler"] == NSOrderedSame) {
      newRule.state = SNTRuleStateAllowCompiler;
    } else if ([arg caseInsensitiveCompare:@"--remove"] == NSOrderedSame) {
      newRule.state = SNTRuleStateRemove;
    } else if ([arg caseInsensitiveCompare:@"--check"] == NSOrderedSame) {
      check = YES;
    } else if ([arg caseInsensitiveCompare:@"--certificate"] == NSOrderedSame) {
      newRule.type = SNTRuleTypeCertificate;
    } else if ([arg caseInsensitiveCompare:@"--path"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--path requires an argument"];
      }
      path = arguments[i];
    } else if ([arg caseInsensitiveCompare:@"--sha256"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--sha256 requires an argument"];
      }
      newRule.shasum = arguments[i];
      if (newRule.shasum.length != 64) {
        [self printErrorUsageAndExit:@"--sha256 requires a valid SHA-256 as the argument"];
      }
    } else if ([arg caseInsensitiveCompare:@"--message"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--message requires an argument"];
      }
      newRule.customMsg = arguments[i];
#ifdef DEBUG
    } else if ([arg caseInsensitiveCompare:@"--force"] == NSOrderedSame) {
      // Don't do anything special.
#endif
    } else {
      [self printErrorUsageAndExit:[@"Unknown argument: " stringByAppendingString:arg]];
    }
  }

  if (check) {
    if (!newRule.shasum) return [self printErrorUsageAndExit:@"--check requires --sha256"];
    return [self printStateOfRule:newRule daemonConnection:self.daemonConn];
  }

  if (path) {
    SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:path];
    if (!fi.path) {
      [self printErrorUsageAndExit:@"Provided path was not a plain file"];
    }

    if (newRule.type == SNTRuleTypeBinary) {
      newRule.shasum = fi.SHA256;
    } else if (newRule.type == SNTRuleTypeCertificate) {
      MOLCodesignChecker *cs = [fi codesignCheckerWithError:NULL];
      newRule.shasum = cs.leafCertificate.SHA256;
    }
  }

  if (newRule.state == SNTRuleStateUnknown) {
    [self printErrorUsageAndExit:@"No state specified"];
  } else if (!newRule.shasum) {
    [self printErrorUsageAndExit:@"Either SHA-256 or path to file must be specified"];
  }

  [[self.daemonConn remoteObjectProxy] databaseRuleAddRules:@[newRule]
                                                 cleanSlate:NO
                                                      reply:^(NSError *error) {
    if (error) {
      printf("Failed to modify rules: %s", [error.localizedDescription UTF8String]);
      LOGD(@"Failure reason: %@", error.localizedFailureReason);
      exit(1);
    } else {
      if (newRule.state == SNTRuleStateRemove) {
        printf("Removed rule for SHA-256: %s.\n", [newRule.shasum UTF8String]);
      } else {
        printf("Added rule for SHA-256: %s.\n", [newRule.shasum UTF8String]);
      }
      exit(0);
    }
  }];
}

- (void)printStateOfRule:(SNTRule *)rule daemonConnection:(MOLXPCConnection *)daemonConn {
  NSString *fileSHA256 = (rule.type == SNTRuleTypeBinary) ? rule.shasum : nil;
  NSString *certificateSHA256 = (rule.type == SNTRuleTypeCertificate) ? rule.shasum : nil;
  dispatch_group_t group = dispatch_group_create();
  dispatch_group_enter(group);
  __block NSMutableString *output;
  [[daemonConn remoteObjectProxy] decisionForFilePath:nil
                                           fileSHA256:fileSHA256
                                    certificateSHA256:certificateSHA256
                                                reply:^(SNTEventState s) {
    output = (SNTEventStateAllow & s) ? @"Allowed".mutableCopy : @"Blocked".mutableCopy;
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
      case SNTEventStateAllowCompiler:
        [output appendString:@" (Compiler)"];
        break;
      case SNTEventStateAllowTransitive:
        [output appendString:@" (Transitive)"];
        break;
      default:
        output = @"None".mutableCopy;
        break;
    }
    if (isatty(STDOUT_FILENO)) {
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
    dispatch_group_leave(group);
  }];
  if (dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    printf("Cannot communicate with daemon");
    exit(1);
  }

  dispatch_group_enter(group);
  [[daemonConn remoteObjectProxy] databaseRuleForBinarySHA256:fileSHA256
                                            certificateSHA256:certificateSHA256
                                                        reply:^(SNTRule *r) {
    if (r.state == SNTRuleStateAllowTransitive) {
      NSDate *date = [NSDate dateWithTimeIntervalSinceReferenceDate:r.timestamp];
      [output appendString:[NSString stringWithFormat:@"\nlast access date: %@", [date description]]];
    }
    dispatch_group_leave(group);
  }];
  if (dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    printf("Cannot communicate with daemon");
    exit(1);
  }

  printf("%s\n", output.UTF8String);
  exit(0);
}

@end
