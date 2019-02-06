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

#import "Source/common/SNTSystemInfo.h"

@implementation SNTSystemInfo

+ (NSString *)serialNumber {
  io_service_t platformExpert = IOServiceGetMatchingService(
      kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
  if (!platformExpert) return nil;

  NSString *serial = CFBridgingRelease(IORegistryEntryCreateCFProperty(
      platformExpert, CFSTR(kIOPlatformSerialNumberKey), kCFAllocatorDefault, 0));

  IOObjectRelease(platformExpert);

  return serial;
}

+ (NSString *)hardwareUUID {
  io_service_t platformExpert = IOServiceGetMatchingService(
      kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
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

#pragma mark - Internal

+ (NSDictionary *)_systemVersionDictionary {
  return [NSDictionary
      dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
}

@end
