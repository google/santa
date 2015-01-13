/// Copyright 2014 Google Inc. All rights reserved.
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

#include <IOKit/kext/KextManager.h>

#import "SNTBinaryInfo.h"
#import "SNTKernelCommon.h"
#import "SNTLogging.h"
#import "SNTXPCConnection.h"
#import "SNTXPCControlInterface.h"

@interface SNTCommandStatus : NSObject<SNTCommand>
@end

@implementation SNTCommandStatus

REGISTER_COMMAND_NAME(@"status");

+ (BOOL)requiresRoot {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Get status about Santa";
}

+ (NSString *)longHelpText {
  return @"Returns status information about Santa.";
}

+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn {

  // Version information
  LOGI(@">>> Versions");
  LOGI(@"%-30s | %@", "santa-driver version", [self kextVersion]);
  LOGI(@"%-30s | %@", "santad version", [self daemonVersion]);
  LOGI(@"%-30s | %@",
       "santactl version",
       [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"]);
  LOGI(@"%-30s | %@", "SantaGUI version", [self guiVersion]);
  LOGI(@"");

  // Kext status
  if (daemonConn) {
    __block uint64_t cacheCount = -1;
    [[daemonConn remoteObjectProxy] cacheCount:^(uint64_t count) {
        cacheCount = count;
    }];
    do { usleep(5000); } while (cacheCount == -1);
    LOGI(@">>> Kernel Info");
    LOGI(@"%-30s | %d", "Kernel cache count", cacheCount);
    LOGI(@"");

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
    LOGI(@">>> Database Info");
    LOGI(@"%-30s | %d", "Binary Rules", binaryRuleCount);
    LOGI(@"%-30s | %d", "Certificate Rules", certRuleCount);
    LOGI(@"%-30s | %d", "Events Pending Upload", eventCount);
    LOGI(@"");
  } else {
    LOGI(@">>> santad is not running, cannot provide any more information.");
  }

  exit(0);
}

+ (NSString *)kextVersion {
  NSDictionary *loadedKexts = CFBridgingRelease(
      KextManagerCopyLoadedKextInfo((__bridge CFArrayRef)@[ @(USERCLIENT_ID) ],
                                    (__bridge CFArrayRef)@[ @"CFBundleVersion" ]));

  if (loadedKexts[@(USERCLIENT_ID)] && loadedKexts[@(USERCLIENT_ID)][@"CFBundleVersion"]) {
    return loadedKexts[@(USERCLIENT_ID)][@"CFBundleVersion"];
  }

  SNTBinaryInfo *driverInfo =
      [[SNTBinaryInfo alloc] initWithPath:@"/System/Library/Extensions/santa-driver.kext"];
  if (driverInfo) {
    return [driverInfo.bundleVersion stringByAppendingString:@" (unloaded)"];
  }

  return @"not found";
}

+ (NSString *)daemonVersion {
  SNTBinaryInfo *daemonInfo = [[SNTBinaryInfo alloc] initWithPath:@"/usr/libexec/santad"];
  return daemonInfo.bundleVersion;
}

+ (NSString *)guiVersion {
  SNTBinaryInfo *guiInfo =
      [[SNTBinaryInfo alloc] initWithPath:@"/Applications/Santa.app/Contents/MacOS/Santa"];
  return guiInfo.bundleVersion;
}

@end
