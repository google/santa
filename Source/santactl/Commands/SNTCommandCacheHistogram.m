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
#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandCacheHistogram : SNTCommand <SNTCommandProtocol>
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
  printf("This command is no longer implemented.");
}

@end

#endif
