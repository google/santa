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

#import "SNTCommand.h"
#import "SNTCommandController.h"

#import "SNTLogging.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@interface SNTCommandFlushCache : SNTCommand<SNTCommandProtocol>
@end

@implementation SNTCommandFlushCache

#ifdef DEBUG
REGISTER_COMMAND_NAME(@"flushcache")
#endif

+ (BOOL)requiresRoot {
  return YES;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Flush the kernel cache.";
}

+ (NSString *)longHelpText {
  return (@"Flushes the in-kernel cache of whitelisted binaries.\n"
          @"Returns 0 if successful, 1 otherwise");
}

- (void)runWithArguments:(NSArray *)arguments {
  [[self.daemonConn remoteObjectProxy] flushCache:^(BOOL success) {
    if (success) {
      LOGI(@"Cache flush requested");
      exit(0);
    } else {
      LOGE(@"Cache flush failed");
      exit(1);
    }
  }];
}

@end
