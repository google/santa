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

#import "SNTEventLog.h"

#include <grp.h>
#include <libproc.h>
#include <pwd.h>
#include <sys/sysctl.h>

#import "MOLCertificate.h"
#import "SNTCachedDecision.h"
#import "SNTCommonEnums.h"
#import "SNTFileInfo.h"
#import "SNTKernelCommon.h"
#import "SNTLogging.h"

@interface SNTEventLog ()
@property NSRegularExpression *sanitizeRegex;

@property NSMutableDictionary *detailStore;
@property NSLock *detailStoreLock;
@end

@implementation SNTEventLog

- (instancetype)init {
  self = [super init];
  if (self) {
    _sanitizeRegex = [NSRegularExpression regularExpressionWithPattern:@"\\||\\n|\\r"
                                                               options:0
                                                                 error:NULL];

    _detailStore = [NSMutableDictionary dictionaryWithCapacity:10000];
    _detailStoreLock = [[NSLock alloc] init];
  }
  return self;
}

- (void)saveDecisionDetails:(SNTCachedDecision *)cd {
  [self.detailStoreLock lock];
  self.detailStore[@(cd.vnodeId)] = cd;
  [self.detailStoreLock unlock];
}

- (void)logFileModification:(santa_message_t)message {
  NSString *action, *newpath;

  NSString *path = @(message.path);

  switch (message.action) {
    case ACTION_NOTIFY_DELETE: {
      action = @"DELETE";
      break;
    }
    case ACTION_NOTIFY_EXCHANGE: {
      action = @"EXCHANGE";
      newpath = @(message.newpath);
      break;
    }
    case ACTION_NOTIFY_LINK: {
      action = @"LINK";
      newpath = @(message.newpath);
      break;
    }
    case ACTION_NOTIFY_RENAME: {
      action = @"RENAME";
      newpath = @(message.newpath);
      break;
    }
    case ACTION_NOTIFY_WRITE: {
      action = @"WRITE";
      break;
    }
    default: action = @"UNKNOWN"; break;
  }

  // init the string with 2k capacity to avoid reallocs
  NSMutableString *outStr = [NSMutableString stringWithCapacity:2048];
  [outStr appendFormat:@"action=%@|path=%@", action, [self sanitizeString:path]];
  if (newpath) {
    [outStr appendFormat:@"|newpath=%@", [self sanitizeString:newpath]];
  }
  char ppath[PATH_MAX] = "(null)";
  proc_pidpath(message.pid, ppath, PATH_MAX);

  NSString *user, *group;
  struct passwd *pw = getpwuid(message.uid);
  if (pw) user = @(pw->pw_name);
  struct group *gr = getgrgid(message.gid);
  if (gr) group = @(gr->gr_name);

  [outStr appendFormat:@"|pid=%d|ppid=%d|process=%s|processpath=%s|uid=%d|user=%@|gid=%d|group=%@",
                       message.pid, message.ppid, message.pname, ppath,
                       message.uid, user, message.gid, group];
  LOGI(@"%@", outStr);
}

- (void)logDeniedExecution:(SNTCachedDecision *)cd withMessage:(santa_message_t)message {
  [self logExecution:message withDecision:cd];
}

- (void)logAllowedExecution:(santa_message_t)message {
  [self.detailStoreLock lock];
  SNTCachedDecision *cd = self.detailStore[@(message.vnode_id)];
  [self.detailStoreLock unlock];
  [self logExecution:message withDecision:cd];
}

- (void)logExecution:(santa_message_t)message withDecision:(SNTCachedDecision *)cd {
  NSString *d, *r, *args;

  switch (cd.decision) {
    case SNTEventStateAllowBinary:
      d = @"ALLOW";
      r = @"BINARY";
      args = [self argsForPid:message.pid];
      break;
    case SNTEventStateAllowCertificate:
      d = @"ALLOW";
      r = @"CERTIFICATE";
      args = [self argsForPid:message.pid];
      break;
    case SNTEventStateAllowScope:
      d = @"ALLOW";
      r = @"SCOPE";
      args = [self argsForPid:message.pid];
      break;
    case SNTEventStateAllowUnknown:
      d = @"ALLOW";
      r = @"UNKNOWN";
      args = [self argsForPid:message.pid];
      break;
    case SNTEventStateBlockBinary:
      d = @"DENY";
      r = @"BINARY";
      break;
    case SNTEventStateBlockCertificate:
      d = @"DENY";
      r = @"CERT";
      break;
    case SNTEventStateBlockScope:
      d = @"DENY";
      r = @"SCOPE";
      break;
    case SNTEventStateBlockUnknown:
      d = @"DENY";
      r = @"UNKNOWN";
      break;
    default:
      d = @"ALLOW";
      r = @"NOTRUNNING";
      args = [self argsForPid:message.pid];
      break;
  }

  // init the string with 4k capacity to avoid reallocs
  NSMutableString *outLog = [[NSMutableString alloc] initWithCapacity:4096];
  [outLog appendFormat:@"action=EXEC|decision=%@|reason=%@", d, r];

  if (cd.decisionExtra) {
    [outLog appendFormat:@"|explain=%@", cd.decisionExtra];
  }

  [outLog appendFormat:@"|sha256=%@|path=%@|args=%@", cd.sha256,
                       [self sanitizeString:@(message.path)],
                       [self sanitizeString:args]];

  if (cd.certSHA256) {
    [outLog appendFormat:@"|cert_sha256=%@|cert_cn=%@", cd.certSHA256,
                         [self sanitizeString:cd.certCommonName]];
  }

  if (cd.quarantineURL) {
    [outLog appendFormat:@"|quarantine_url=%@",
                         [self sanitizeString:cd.quarantineURL]];
  }

  NSString *user, *group;
  struct passwd *pw = getpwuid(message.uid);
  if (pw) user = @(pw->pw_name);
  struct group *gr = getgrgid(message.gid);
  if (gr) group = @(gr->gr_name);

  [outLog appendFormat:@"|pid=%d|ppid=%d|uid=%d|user=%@|gid=%d|group=%@",
                       message.pid, message.ppid, message.uid, user,
                       message.gid, group];

  LOGI(@"%@", outLog);
}

- (void)logDiskAppeared:(NSDictionary *)diskProperties {
  if (![diskProperties[@"DAVolumeMountable"] boolValue]) return;

  NSString *dmgPath = @"";
  NSString *serial = @"";
  if ([diskProperties[@"DADeviceModel"] isEqual:@"Disk Image"]) {
    dmgPath = [self diskImageForDevice:diskProperties[@"DADevicePath"]];
  } else {
    serial = [self serialForDevice:diskProperties[@"DADevicePath"]];
    serial = [serial stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
  }

  NSString *model = [NSString stringWithFormat:@"%@ %@",
                        diskProperties[@"DADeviceVendor"] ?: @"",
                        diskProperties[@"DADeviceModel"] ?: @""];
  model = [model stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  LOGI(@"action=DISKAPPEAR|mount=%@|volume=%@|bsdname=%@|fs=%@|model=%@|serial=%@|bus=%@|dmgpath=%@",
       [diskProperties[@"DAVolumePath"] path] ?: @"",
       diskProperties[@"DAVolumeName"] ?: @"",
       diskProperties[@"DAMediaBSDName"] ?: @"",
       diskProperties[@"DAVolumeKind"] ?: @"",
       model ?: @"",
       serial,
       diskProperties[@"DADeviceProtocol"] ?: @"",
       dmgPath);
}

- (void)logDiskDisappeared:(NSDictionary *)diskProperties {
  if (![diskProperties[@"DAVolumeMountable"] boolValue]) return;

  LOGI(@"action=DISKDISAPPEAR|mount=%@|volume=%@|bsdname=%@",
       [diskProperties[@"DAVolumePath"] path] ?: @"",
       diskProperties[@"DAVolumeName"] ?: @"",
       diskProperties[@"DAMediaBSDName"]);
}

#pragma mark Helpers

- (NSString *)sanitizeString:(NSString *)inStr {
  if (!inStr) return inStr;

  NSMutableString *str = [inStr mutableCopy];

  NSArray *matches = [self.sanitizeRegex matchesInString:inStr
                                                 options:0
                                                   range:NSMakeRange(0, inStr.length)];

  NSInteger offset = 0;
  for (NSTextCheckingResult *result in matches) {
    NSRange range = result.range;
    range.location += offset;

    NSString *match = [self.sanitizeRegex replacementStringForResult:result
                                                            inString:str
                                                              offset:offset
                                                            template:@"$0"];
    NSString *replacement;
    if ([match isEqualToString:@"|"]) {
      replacement = @"<pipe>";
    } else if ([match isEqualToString:@"\n"]) {
      replacement = @"\\n";
    } else if ([match isEqualToString:@"\r"]) {
      replacement = @"\\r";
    }

    [str replaceCharactersInRange:range withString:replacement];

    offset += (replacement.length - range.length);
  }

  return str;
}

/**
  Use sysctl to get the arguments for a PID, returned as a single string.
*/
- (NSString *)argsForPid:(pid_t)pid {
  size_t argsSize = 0, index = 0;
  NSMutableData *argsData;
  char *bytes = NULL;

  // Repeat up to 3 times, sysctl will sometimes return nothing
  // while still giving a success error code
  int tries = 3;
  do {
    int mib[] = {CTL_KERN, KERN_PROCARGS2, pid};
    // Get length of arg array
    if (sysctl(mib, 3, NULL, &argsSize, NULL, 0) < 0) continue;
    argsSize++;

    // Allocate space to store the args
    argsData = [NSMutableData dataWithLength:argsSize];
    bytes = argsData.mutableBytes;

    // Get the args
    if (sysctl(mib, 3, bytes, &argsSize, NULL, 0) < 0) continue;
  } while (argsSize == argsData.length && tries--);
  if (bytes == NULL) return nil;

  // Get argc, set index to the end of argc
  int argc = 0;
  memcpy(&argc, &bytes[0], sizeof(argc));
  index = sizeof(argc);

  // Skip past end of executable path and trailing NULLs
  for (; index < argsSize; ++index) {
    if (bytes[index] == '\0') {
      ++index;
      break;
    }
  }
  for (; index < argsSize; ++index) {
    if (bytes[index] != '\0') break;
  }

  // Save the beginning of the arguments
  size_t stringStart = index;

  // Replace all NULLs with spaces up until the first environment variable
  int replacedNulls = 0;
  for (; index < argsSize; ++index) {
    if (bytes[index] == '\0') {
      bytes[index] = ' ';
      ++replacedNulls;
      if (replacedNulls == argc) break;
    }
  }

  // Copy the bytes from 'stringStart' to 'index' into a string, return it.
  return [[NSString alloc] initWithBytes:&bytes[stringStart]
                                  length:(index - stringStart)
                                encoding:NSUTF8StringEncoding];
}

/**
  Given an IOKit device path (like those provided by DiskArbitration), find the disk
  image path by looking up the device in the IOKit registry and getting its properties.

  This is largely the same as the way hdiutil gathers info for the "info" command.
*/
- (NSString *)diskImageForDevice:(NSString *)devPath {
  devPath = [devPath stringByDeletingLastPathComponent];
  if (!devPath.length) return nil;
  io_registry_entry_t device = IORegistryEntryFromPath(kIOMasterPortDefault, devPath.UTF8String);
  CFMutableDictionaryRef deviceProperties = NULL;
  IORegistryEntryCreateCFProperties(device, &deviceProperties, kCFAllocatorDefault, kNilOptions);
  NSDictionary *properties = CFBridgingRelease(deviceProperties);
  IOObjectRelease(device);

  NSData *pathData = properties[@"image-path"];
  NSString *result = [[NSString alloc] initWithData:pathData encoding:NSUTF8StringEncoding];

  return result;
}

/**
 Given an IOKit device path (like those provided by DiskArbitration), find the device serial number,
 if there is one. This has only really been tested with USB and internal devices.
*/
- (NSString *)serialForDevice:(NSString *)devPath {
  if (!devPath.length) return nil;
  NSString *serial;
  io_registry_entry_t device = IORegistryEntryFromPath(kIOMasterPortDefault, devPath.UTF8String);
  while (!serial && device) {
    CFMutableDictionaryRef deviceProperties = NULL;
    IORegistryEntryCreateCFProperties(device, &deviceProperties, kCFAllocatorDefault, kNilOptions);
    NSDictionary *properties = CFBridgingRelease(deviceProperties);
    if (properties[@"Serial Number"]) {
      serial = properties[@"Serial Number"];
    } else if (properties[@"kUSBSerialNumberString"]) {
      serial = properties[@"kUSBSerialNumberString"];
    }

    if (serial) {
      IOObjectRelease(device);
      break;
    }

    io_registry_entry_t parent;
    IORegistryEntryGetParentEntry(device, kIOServicePlane, &parent);
    IOObjectRelease(device);
    device = parent;
  }

  return serial;
}

@end
