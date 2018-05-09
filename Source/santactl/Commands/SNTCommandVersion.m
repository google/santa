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
#import <IOKit/kext/KextManager.h>

#import "SNTCommand.h"
#import "SNTCommandController.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "SNTCommonEnums.h"
#import "SNTFileInfo.h"
#import "SNTKernelCommon.h"

@interface SNTCommandVersion : SNTCommand<SNTCommandProtocol>
@end

@implementation SNTCommandVersion

REGISTER_COMMAND_NAME(@"version")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Show Santa component versions.";
}

+ (NSString *)longHelpText {
  return (@"Show versions of all Santa components.\n"
          @"  Use --json to output in JSON format.");
}

- (void)runWithArguments:(NSArray *)arguments {
  if ([arguments containsObject:@"--json"]) {
    NSDictionary *versions = @{
      @"santa-driver" : [self santaKextVersion],
      @"santad" : [self santadVersion],
      @"santactl" : [self santactlVersion],
      @"SantaGUI" : [self santaAppVersion],
    };
    NSData *versionsData = [NSJSONSerialization dataWithJSONObject:versions
                                                           options:NSJSONWritingPrettyPrinted
                                                             error:nil];
    NSString *versionsStr = [[NSString alloc] initWithData:versionsData
                                                  encoding:NSUTF8StringEncoding];
    printf("%s\n", [versionsStr UTF8String]);
  } else {
    printf("%-15s | %s\n", "santa-driver", [[self santaKextVersion] UTF8String]);
    printf("%-15s | %s\n", "santad", [[self santadVersion] UTF8String]);
    printf("%-15s | %s\n", "santactl", [[self santactlVersion] UTF8String]);
    printf("%-15s | %s\n", "SantaGUI", [[self santaAppVersion] UTF8String]);
  }
  exit(0);
}

- (NSString *)santaKextVersion {
  NSDictionary *loadedKexts = CFBridgingRelease(
      KextManagerCopyLoadedKextInfo((__bridge CFArrayRef) @[ @(USERCLIENT_ID) ],
                                    (__bridge CFArrayRef) @[ @"CFBundleVersion" ]));

  if (loadedKexts[@(USERCLIENT_ID)][@"CFBundleVersion"]) {
    return loadedKexts[@(USERCLIENT_ID)][@"CFBundleVersion"];
  }

  SNTFileInfo *driverInfo = [[SNTFileInfo alloc] initWithPath:@(kKextPath)];
  if (driverInfo) {
    return [driverInfo.bundleVersion stringByAppendingString:@" (unloaded)"];
  }

  return @"not found";
}

- (NSString *)santadVersion {
  SNTFileInfo *daemonInfo = [[SNTFileInfo alloc] initWithPath:@(kSantaDPath)];
  return daemonInfo.bundleVersion;
}

- (NSString *)santaAppVersion {
  SNTFileInfo *guiInfo =
      [[SNTFileInfo alloc] initWithPath:@"/Applications/Santa.app/Contents/MacOS/Santa"];
  return guiInfo.bundleVersion;
}

- (NSString *)santactlVersion {
  return [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
}

@end
