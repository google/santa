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
#import "SNTConfigurator.h"
#import "SNTDropRootPrivs.h"
#import "SNTFileInfo.h"
#import "SNTRule.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"


@interface SNTCommandRule : NSObject<SNTCommand>
@property SNTXPCConnection *daemonConn;
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
  return @"Manually add/remove rules.";
}

+ (NSString *)longHelpText {
  return (@"Usage: santactl rule {add|remove} [options]\n"
          @"  --whitelist: add to whitelist\n"
          @"  --blacklist: add to blacklist\n"
          @"  --silent-blacklist: add to silent blacklist\n"
          @"  --message {message}: custom message\n"
          @"  --path {path}: path of binary to add\n"
          @"  --sha256 {sha256}: hash to add\n");
}

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  SNTConfigurator *config = [SNTConfigurator configurator];

  // Ensure we have no privileges
  if (!DropRootPrivileges()) {
    printf("Failed to drop root privileges.\n");
    exit(1);
  }

  if ([config syncBaseURL] != nil) {
    printf("SyncBaseURL is set, rules are managed centrally.\n");
    exit(1);
  }

  NSString *action = [arguments firstObject];

  // add or remove
  if (!action) {
    printf("Missing action - add or remove?\n");
    exit(1);
  }

  int state = RULESTATE_UNKNOWN;

  if ([action compare:@"add" options:NSCaseInsensitiveSearch] == NSOrderedSame) {
  } else if ([action compare:@"remove" options:NSCaseInsensitiveSearch] == NSOrderedSame) {
    state = RULESTATE_REMOVE;
  } else {
    printf("Unknown action, expected add or remove.\n");
    exit(1);
  }

  NSString *customMsg = @"";
  NSString *SHA256 = nil;
  NSString *filePath = nil;

  // parse arguments
  for (NSUInteger i = 1; i < [arguments count] ; i++ ) {
    NSString* argument = [arguments objectAtIndex:i];

    if ([argument compare:@"--whitelist" options:NSCaseInsensitiveSearch] == NSOrderedSame) {
      state = RULESTATE_WHITELIST;
    } else if ([argument compare:@"--blacklist" options:NSCaseInsensitiveSearch] == NSOrderedSame) {
      state = RULESTATE_BLACKLIST;
    } else if ([argument compare:@"--silent-blacklist" options:NSCaseInsensitiveSearch] == NSOrderedSame) {
      state = RULESTATE_SILENT_BLACKLIST;
    } else if ([argument compare:@"--message" options:NSCaseInsensitiveSearch] == NSOrderedSame) {
      if (++i > ([arguments count])) {
        printf("No message specified.\n");
      }

      customMsg = [arguments objectAtIndex:i];
    } else if ([argument compare:@"--path" options:NSCaseInsensitiveSearch] == NSOrderedSame) {
      if (++i > ([arguments count])) {
        printf("No path specified.\n");
      }

      filePath = [arguments objectAtIndex:i];
    } else if ([argument compare:@"--sha256" options:NSCaseInsensitiveSearch] == NSOrderedSame) {
      if (++i > ([arguments count])) {
        printf("No SHA-256 specified.\n");
      }

      SHA256 = [arguments objectAtIndex:i];
    } else {
      printf("Unknown argument %s.\n", [argument UTF8String]);
      exit(1);
    }
  }

  if (state == RULESTATE_UNKNOWN) {
    printf("No state specified.\n");
    exit(1);
  }

  if (filePath) {
    SNTFileInfo *fileInfo = [[SNTFileInfo alloc] initWithPath:filePath];
    if (!fileInfo) {
      printf("Not a regular file or executable bundle.\n");
      exit(1);
    }

    SHA256 = [fileInfo SHA256];
  } else if (SHA256) {
  } else {
    printf("No SHA-256 or binary specified.\n");
    exit(1);
  }

  SNTRule *newRule = [[SNTRule alloc] init];
  newRule.shasum = SHA256;
  newRule.state = state;
  newRule.type = RULETYPE_BINARY;
  newRule.customMsg = customMsg;

  [[daemonConn remoteObjectProxy] databaseRuleAddRule:newRule cleanSlate:NO reply:^{
      if (state == RULESTATE_REMOVE) {
        printf("Removed rule for SHA-256: %s.\n", [newRule.shasum UTF8String]);
      } else {
        printf("Added rule for SHA-256: %s.\n", [newRule.shasum UTF8String]);
      }
      exit(0);
  }];
}

@end
