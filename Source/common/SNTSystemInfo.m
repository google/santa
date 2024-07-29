/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#import "Source/common/SNTSystemInfo.h"
#include <sys/sysctl.h>

@implementation SNTSystemInfo

+ (NSString *)serialNumber {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  io_service_t platformExpert =
    IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
#pragma clang diagnostic pop
  if (!platformExpert) return nil;

  NSString *serial = CFBridgingRelease(IORegistryEntryCreateCFProperty(
    platformExpert, CFSTR(kIOPlatformSerialNumberKey), kCFAllocatorDefault, 0));

  IOObjectRelease(platformExpert);

  return serial;
}

+ (NSString *)hardwareUUID {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  io_service_t platformExpert =
    IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
#pragma clang diagnostic pop
  if (!platformExpert) return nil;

  NSString *uuid = CFBridgingRelease(IORegistryEntryCreateCFProperty(
    platformExpert, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0));

  IOObjectRelease(platformExpert);

  return uuid;
}

+ (NSString *)osVersion {
  return [SNTSystemInfo _systemVersionDictionary][@"ProductVersion"];
}

+ (NSString *)osBuild {
  return [SNTSystemInfo _systemVersionDictionary][@"ProductBuildVersion"];
}

+ (NSString *)shortHostname {
  return [[[SNTSystemInfo longHostname] componentsSeparatedByString:@"."] firstObject];
}

+ (NSString *)longHostname {
  char hostname[MAXHOSTNAMELEN];
  gethostname(hostname, (int)sizeof(hostname));
  return @(hostname);
}

+ (NSString *)modelIdentifier {
  char model[32];
  size_t len = 32;
  sysctlbyname("hw.model", model, &len, NULL, 0);
  return @(model);
}

+ (NSString *)santaProductVersion {
  NSDictionary *info_dict = [[NSBundle mainBundle] infoDictionary];
  return info_dict[@"CFBundleShortVersionString"];
}

+ (NSString *)santaBuildVersion {
  NSDictionary *info_dict = [[NSBundle mainBundle] infoDictionary];
  return [[info_dict[@"CFBundleVersion"] componentsSeparatedByString:@"."] lastObject];
}

+ (NSString *)santaFullVersion {
  NSDictionary *info_dict = [[NSBundle mainBundle] infoDictionary];
  return info_dict[@"CFBundleVersion"];
}

#pragma mark - Internal

+ (NSDictionary *)_systemVersionDictionary {
  return
    [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
}

@end
