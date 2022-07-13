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

@interface SNTCommandRule : SNTCommand <SNTCommandProtocol>
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
          @"    --identifier {sha256|teamID}: identifier to add/remove/check\n"
          @"    --sha256 {sha256}: hash to add/remove/check [deprecated]\n"
          @"\n"
          @"  Optionally:\n"
          @"    --teamid: add or check a team ID rule instead of binary\n"
          @"    --certificate: add or check a certificate sha256 rule instead of binary\n"
#ifdef DEBUG
          @"    --force: allow manual changes even when SyncBaseUrl is set\n"
#endif
          @"    --message {message}: custom message\n");
}

- (void)runWithArguments:(NSArray *)arguments {
  SNTConfigurator *config = [SNTConfigurator configurator];
  if ((config.syncBaseURL || config.staticRules.count) && ![arguments containsObject:@"--check"]
#ifdef DEBUG
      // DEBUG builds add a --force flag to allow manually adding/removing rules during testing.
      && ![arguments containsObject:@"--force"]) {
#else
      ) {
#endif
    printf("(SyncBaseURL/StaticRules is set, rules are managed centrally.)");
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

    if ([arg caseInsensitiveCompare:@"--allow"] == NSOrderedSame ||
        [arg caseInsensitiveCompare:@"--whitelist"] == NSOrderedSame) {
      newRule.state = SNTRuleStateAllow;
    } else if ([arg caseInsensitiveCompare:@"--block"] == NSOrderedSame ||
               [arg caseInsensitiveCompare:@"--blacklist"] == NSOrderedSame) {
      newRule.state = SNTRuleStateBlock;
    } else if ([arg caseInsensitiveCompare:@"--silent-block"] == NSOrderedSame ||
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
    } else if ([arg caseInsensitiveCompare:@"--teamid"] == NSOrderedSame) {
      newRule.type = SNTRuleTypeTeamID;
    } else if ([arg caseInsensitiveCompare:@"--path"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--path requires an argument"];
      }
      path = arguments[i];
    } else if ([arg caseInsensitiveCompare:@"--identifier"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--identifier requires an argument"];
      }
      newRule.identifier = arguments[i];
    } else if ([arg caseInsensitiveCompare:@"--sha256"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--sha256 requires an argument"];
      }
      newRule.identifier = arguments[i];
      if (newRule.identifier.length != 64) {
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
    if (!newRule.identifier) return [self printErrorUsageAndExit:@"--check requires --identifier"];
    return [self printStateOfRule:newRule daemonConnection:self.daemonConn];
  }

  if (path) {
    SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:path];
    if (!fi.path) {
      [self printErrorUsageAndExit:@"Provided path was not a plain file"];
    }

    if (newRule.type == SNTRuleTypeBinary) {
      newRule.identifier = fi.SHA256;
    } else if (newRule.type == SNTRuleTypeCertificate) {
      MOLCodesignChecker *cs = [fi codesignCheckerWithError:NULL];
      newRule.identifier = cs.leafCertificate.SHA256;
    } else if (newRule.type == SNTRuleTypeTeamID) {
    }
  }

  if (newRule.state == SNTRuleStateUnknown) {
    [self printErrorUsageAndExit:@"No state specified"];
  } else if (!newRule.identifier) {
    [self printErrorUsageAndExit:@"Either SHA-256, team ID, or path to file must be specified"];
  }

  [[self.daemonConn remoteObjectProxy]
    databaseRuleAddRules:@[ newRule ]
              cleanSlate:NO
                   reply:^(NSError *error) {
                     if (error) {
                       printf("Failed to modify rules: %s",
                              [error.localizedDescription UTF8String]);
                       LOGD(@"Failure reason: %@", error.localizedFailureReason);
                       exit(1);
                     } else {
                       NSString *ruleType;
                       switch (newRule.type) {
                         case SNTRuleTypeCertificate:
                         case SNTRuleTypeBinary: {
                           ruleType = @"SHA-256";
                           break;
                         }
                         case SNTRuleTypeTeamID: {
                           ruleType = @"Team ID";
                           break;
                         }
                         default: ruleType = @"(Unknown type)";
                       }
                       if (newRule.state == SNTRuleStateRemove) {
                         printf("Removed rule for %s: %s.\n", [ruleType UTF8String],
                                [newRule.identifier UTF8String]);
                       } else {
                         printf("Added rule for %s: %s.\n", [ruleType UTF8String],
                                [newRule.identifier UTF8String]);
                       }
                       exit(0);
                     }
                   }];
}

- (void)printStateOfRule:(SNTRule *)rule daemonConnection:(MOLXPCConnection *)daemonConn {
  NSString *fileSHA256 = (rule.type == SNTRuleTypeBinary) ? rule.identifier : nil;
  NSString *certificateSHA256 = (rule.type == SNTRuleTypeCertificate) ? rule.identifier : nil;
  NSString *teamID = (rule.type == SNTRuleTypeTeamID) ? rule.identifier : nil;
  dispatch_group_t group = dispatch_group_create();
  dispatch_group_enter(group);
  __block NSMutableString *output;
  [[daemonConn remoteObjectProxy] decisionForFilePath:nil
                                           fileSHA256:fileSHA256
                                    certificateSHA256:certificateSHA256
                                               teamID:teamID
                                                reply:^(SNTEventState s) {
                                                  output = (SNTEventStateAllow & s)
                                                             ? @"Allowed".mutableCopy
                                                             : @"Blocked".mutableCopy;
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
                                                    case SNTEventStateAllowTeamID:
                                                    case SNTEventStateBlockTeamID:
                                                      [output appendString:@" (TeamID)"];
                                                      break;
                                                    default: output = @"None".mutableCopy; break;
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
  [[daemonConn remoteObjectProxy]
    databaseRuleForBinarySHA256:fileSHA256
              certificateSHA256:certificateSHA256
                         teamID:teamID
                          reply:^(SNTRule *r) {
                            if (r.state == SNTRuleStateAllowTransitive) {
                              NSDate *date =
                                [NSDate dateWithTimeIntervalSinceReferenceDate:r.timestamp];
                              [output
                                appendString:[NSString stringWithFormat:@"\nlast access date: %@",
                                                                        [date description]]];
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
