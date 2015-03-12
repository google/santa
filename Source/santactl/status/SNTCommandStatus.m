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

#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@interface SNTCommandStatus : NSObject<SNTCommand>
@end

@implementation SNTCommandStatus

REGISTER_COMMAND_NAME(@"status");

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Get status about Santa";
}

+ (NSString *)longHelpText {
  return @"Returns status information about Santa.";
}

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  // Kext status
  __block uint64_t cacheCount = -1;
  [[daemonConn remoteObjectProxy] cacheCount:^(uint64_t count) {
      cacheCount = count;
  }];
  do { usleep(5000); } while (cacheCount == -1);
  printf(">>> Kernel Info\n");
  printf("  %-25s | %lld\n", "Kernel cache count", cacheCount);

  // Database counts
  __block uint64_t eventCount = 1, binaryRuleCount = -1, certRuleCount = -1;
  [[daemonConn remoteObjectProxy] databaseRuleCounts:^(uint64_t binary, uint64_t certificate) {
      binaryRuleCount = binary;
      certRuleCount = certificate;
  }];
  [[daemonConn remoteObjectProxy] databaseEventCount:^(uint64_t count) {
      eventCount = count;
  }];
  do { usleep(5000); } while (eventCount == -1 || binaryRuleCount == -1 || certRuleCount == -1);

  printf(">>> Database Info\n");
  printf("  %-25s | %lld\n", "Binary Rules", binaryRuleCount);
  printf("  %-25s | %lld\n", "Certificate Rules", certRuleCount);
  printf("  %-25s | %lld\n", "Events Pending Upload", eventCount);

  exit(0);
}

@end
