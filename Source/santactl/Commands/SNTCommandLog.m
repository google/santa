/// Copyright 2017 Google Inc. All rights reserved.
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

#import "SNTKernelCommon.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@interface SNTCommandLog : NSObject<SNTCommand>
@end

@implementation SNTCommandLog

REGISTER_COMMAND_NAME(@"log")

+ (BOOL)requiresRoot {
  return YES;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Sets log types";
}

+ (NSString *)longHelpText {
  return (@"Usage: santactl log [options]\n"
          @"  One of:\n"
          @"    --enable:  [all, write, rename, exchange, link, delete]\n"
          @"    --disable: [all, write, rename, exchange, link, delete]\n");
}

+ (void)printErrorUsageAndExit:(NSString *)error {
  printf("%s\n\n", [error UTF8String]);
  printf("%s\n", [[self longHelpText] UTF8String]);
  exit(1);
}

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  NSArray *flags;
  BOOL enable = NO;

  // Parse arguments
  for (NSUInteger i = 0; i < arguments.count; ++i) {
    NSString *arg = arguments[i];

    if ([arg caseInsensitiveCompare:@"--enable"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--enable requires an argument"];
      }
      enable = YES;
      flags = [arguments subarrayWithRange:NSMakeRange(i, arguments.count - 1)];
      break;
    } else if ([arg caseInsensitiveCompare:@"--disable"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--disable requires an argument"];
      }
      flags = [arguments subarrayWithRange:NSMakeRange(i, arguments.count - 1)];
      break;
    } else {
      [self printErrorUsageAndExit:[@"Unknown argument: " stringByAppendingString:arg]];
    }
  }

  NSDictionary *flagMap = @{
    @"all" : @(kFilterLogAll),
    @"write" : @(kFileopLogWrite),
    @"rename" : @(kFileopLogRename),
    @"exchange" : @(kFileopLogExchange),
    @"link" : @(kFileopLogLink),
    @"delete" : @(kFileopLogDelete)
  };

  fileop_log_filter_t filter = enable ? kFilterLogNone : kFilterLogAll;
  for (NSString *f in flags) {
    if (![flagMap.allKeys containsObject:f]) {
      [self printErrorUsageAndExit:[NSString stringWithFormat:@"Invalid flag: %@", f]];
    }
    if ([f isEqualToString:@"all"] && flags.count > 1) {
      [self printErrorUsageAndExit:@"Use all by itself"];
    }
    if (enable) {
      filter |= [flagMap[f] unsignedIntValue];
    } else {
      filter ^= [flagMap[f] unsignedIntValue];
    }
  }

  [[daemonConn remoteObjectProxy] setFileopLoggingFilter:filter withReply:^{
    printf("Success, set filter to: 0x%08x Enabled log types: ", filter);
    for (NSString *f in flagMap.allKeys) {
      if (filter & [flagMap[f] unsignedIntValue] && ![f isEqualToString:@"all"]) {
        printf("%s ", f.UTF8String);
      }
    }
    printf("\n");
    exit(0);
  }];
}

@end