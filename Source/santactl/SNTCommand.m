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

#import "Source/santactl/SNTCommand.h"

@implementation SNTCommand

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(MOLXPCConnection *)daemonConn {
  id cmd = [[self alloc] initWithDaemonConnection:daemonConn];
  [cmd runWithArguments:arguments];
}

- (instancetype)initWithDaemonConnection:(MOLXPCConnection *)daemonConn {
  self = [super init];
  if (self) {
    _daemonConn = daemonConn;
  }
  return self;
}

- (void)runWithArguments:(NSArray *)arguments {
  // This method must be overridden.
  [self doesNotRecognizeSelector:_cmd];
}

- (void)printErrorUsageAndExit:(NSString *)error {
  fprintf(stderr, "%s\n\n", [error UTF8String]);
  fprintf(stderr, "%s\n", [[[self class] longHelpText] UTF8String]);
  exit(1);
}

@end
