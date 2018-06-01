/// Copyright 2018 Google Inc. All rights reserved.
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

#ifdef DEBUG

#import <Foundation/Foundation.h>

#import "SNTCommand.h"
#import "SNTCommandController.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "SNTLogging.h"
#import "SNTXPCControlInterface.h"

@interface SNTCommandCacheHistogram : SNTCommand<SNTCommandProtocol>
@end

@implementation SNTCommandCacheHistogram

REGISTER_COMMAND_NAME(@"cachehistogram")

+ (BOOL)requiresRoot {
  return YES;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Print a cache distribution histogram.";
}

+ (NSString *)longHelpText {
  return (@"Prints a histogram of each bucket of the in-kernel cache\n"
          @"  Use -g to get 'graphical' output\n"
          @"Only available in DEBUG builds.");
}

- (void)runWithArguments:(NSArray *)arguments {
  [[self.daemonConn remoteObjectProxy] cacheBucketCount:^(NSArray *counts) {
    NSMutableDictionary<NSNumber *, NSNumber *> *k = [NSMutableDictionary dictionary];
    [counts enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
      if (!k[obj]) {
        k[obj] = @1;
      } else {
        k[obj] = @([k[obj] intValue] + 1);
      }
    }];
    printf("There are %llu empty buckets\n", [k[@0] unsignedLongLongValue]);
    for (unsigned long x = 1; x < k.count; ++x) {
      uint64_t kv = [k[@(x)] unsignedLongLongValue];
      if ([[[NSProcessInfo processInfo] arguments] containsObject:@"-g"]) {
        printf("%4lu: ", x);
        for (uint64_t y = 0; y < kv; ++y) {
          printf("#");
        }
        printf("\n");
      } else {
        printf("%4lu: %llu\n", x ,kv);
      }
    }
    exit(0);
  }];
}

@end

#endif
