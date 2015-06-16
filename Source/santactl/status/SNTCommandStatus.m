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

REGISTER_COMMAND_NAME(@"status")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Show Santa status information.";
}

+ (NSString *)longHelpText {
  return nil;
}

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {
  // Daemon status
  __block NSString *clientMode;
  [[daemonConn remoteObjectProxy] clientMode:^(santa_clientmode_t cm) {
      switch (cm) {
        case CLIENTMODE_MONITOR:
          clientMode = @"Monitor"; break;
        case CLIENTMODE_LOCKDOWN:
          clientMode = @"Lockdown"; break;
        default:
          clientMode = [NSString stringWithFormat:@"Unknown (%d)", cm]; break;
      }
  }];
  do { usleep(5000); } while (!clientMode);
  printf(">>> Daemon Info\n");
  printf("  %-25s | %s\n", "Mode", [clientMode UTF8String]);

  // Kext status
  __block int64_t cacheCount = -1;
  [[daemonConn remoteObjectProxy] cacheCount:^(int64_t count) {
      cacheCount = count;
  }];
  do { usleep(5000); } while (cacheCount == -1);
  printf(">>> Kernel Info\n");
  printf("  %-25s | %lld\n", "Kernel cache count", cacheCount);

  // Database counts
  __block int64_t eventCount = -1, binaryRuleCount = -1, certRuleCount = -1;
  [[daemonConn remoteObjectProxy] databaseRuleCounts:^(int64_t binary, int64_t certificate) {
      binaryRuleCount = binary;
      certRuleCount = certificate;
  }];
  [[daemonConn remoteObjectProxy] databaseEventCount:^(int64_t count) {
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
