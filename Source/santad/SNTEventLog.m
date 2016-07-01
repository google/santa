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
@property NSMutableDictionary *detailStore;
@property dispatch_queue_t detailStoreQueue;
@end

@implementation SNTEventLog

- (instancetype)init {
  self = [super init];
  if (self) {
    _detailStore = [NSMutableDictionary dictionaryWithCapacity:10000];
    _detailStoreQueue = dispatch_queue_create("com.google.santad.detail_store",
                                              DISPATCH_QUEUE_SERIAL);
  }
  return self;
}

- (void)saveDecisionDetails:(SNTCachedDecision *)cd {
  dispatch_sync(self.detailStoreQueue, ^{
    self.detailStore[@(cd.vnodeId)] = cd;
  });
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

  const char *user = "";
  const char *group = "";
  struct passwd *pw = getpwuid(message.uid);
  if (pw) user = pw->pw_name;
  struct group *gr = getgrgid(message.gid);
  if (gr) group = gr->gr_name;

  [outStr appendFormat:@"|pid=%d|ppid=%d|process=%s|processpath=%s|uid=%d|user=%s|gid=%d|group=%s",
                       message.pid, message.ppid, message.pname, ppath,
                       message.uid, user, message.gid, group];
  LOGI(@"%@", outStr);
}

- (void)logDeniedExecution:(SNTCachedDecision *)cd withMessage:(santa_message_t)message {
  [self logExecution:message withDecision:cd];
}

- (void)logAllowedExecution:(santa_message_t)message {
  __block SNTCachedDecision *cd;
  dispatch_sync(self.detailStoreQueue, ^{
    cd = self.detailStore[@(message.vnode_id)];
  });
  [self logExecution:message withDecision:cd];
}

- (void)logExecution:(santa_message_t)message withDecision:(SNTCachedDecision *)cd {
  NSString *d, *r;
  BOOL logArgs = NO;

  switch (cd.decision) {
    case SNTEventStateAllowBinary:
      d = @"ALLOW";
      r = @"BINARY";
      logArgs = YES;
      break;
    case SNTEventStateAllowCertificate:
      d = @"ALLOW";
      r = @"CERTIFICATE";
      logArgs = YES;
      break;
    case SNTEventStateAllowScope:
      d = @"ALLOW";
      r = @"SCOPE";
      logArgs = YES;
      break;
    case SNTEventStateAllowUnknown:
      d = @"ALLOW";
      r = @"UNKNOWN";
      logArgs = YES;
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
      logArgs = YES;
      break;
  }

  // init the string with 4k capacity to avoid reallocs
  NSMutableString *outLog = [[NSMutableString alloc] initWithCapacity:4096];
  [outLog appendFormat:@"action=EXEC|decision=%@|reason=%@", d, r];

  if (cd.decisionExtra) {
    [outLog appendFormat:@"|explain=%@", cd.decisionExtra];
  }

  [outLog appendFormat:@"|sha256=%@|path=%@", cd.sha256, [self sanitizeString:@(message.path)]];

  if (logArgs) {
    [self addArgsForPid:message.pid toString:outLog];
  }

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

/**
  Sanitizes a given string if necessary, otherwise returns the original.
*/
- (NSString *)sanitizeString:(NSString *)inStr {
  NSUInteger length = [inStr lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
  if (length < 1) return inStr;

  NSString *ret = [self sanitizeCString:inStr.UTF8String ofLength:length];
  if (ret) {
    return ret;
  }
  return inStr;
}

/**
  Sanitize the given C-string, replacing |, \n and \r characters.

  @return a new NSString with the replaced contents, if necessary, otherwise nil.
*/
- (NSString *)sanitizeCString:(const char *)str ofLength:(NSUInteger)length {
  NSUInteger bufOffset = 0, strOffset = 0;
  char c = 0;
  char *buf = NULL;
  BOOL shouldFree = NO;

  // Loop through the string one character at a time, looking for the characters
  // we want to remove.
  for (const char *p = str; (c = *p) != 0; ++p) {
    if (c == '|' || c == '\n' || c == '\r') {
      if (!buf) {
        // If string size * 6 is more than 64KiB use malloc, otherwise use stack space.
        if (length * 6 > 64 * 1024) {
          buf = malloc(length * 6);
          shouldFree = YES;
        } else {
          buf = alloca(length * 6);
        }
      }

      // Copy from the last offset up to the character we just found into the buffer
      ptrdiff_t diff = p - str;
      memcpy(buf + bufOffset, str + strOffset, diff - strOffset);

      // Update the buffer and string offsets
      bufOffset += diff - strOffset;
      strOffset = diff + 1;

      // Replace the found character and advance the buffer offset
      switch (c) {
        case '|':
          memcpy(buf + bufOffset, "<pipe>", 6);
          bufOffset += 6;
          break;
        case '\n':
          memcpy(buf + bufOffset, "\\n", 2);
          bufOffset += 2;
          break;
        case '\r':
          memcpy(buf + bufOffset, "\\r", 2);
          bufOffset += 2;
          break;
      }
    }
  }

  if (strOffset > 0 && strOffset < length) {
    // Copy any characters from the last match to the end of the string into the buffer.
    memcpy(buf + bufOffset, str + strOffset, length - strOffset);
    bufOffset += length - strOffset;
  }

  if (buf) {
    // Only return a new string if there were matches
    NSString *ret = [[NSString alloc] initWithBytes:buf
                                             length:bufOffset
                                           encoding:NSUTF8StringEncoding];
    if (shouldFree) {
      free(buf);
    }

    return ret;
  }
  return nil;
}

/**
  Use sysctl to get the arguments for a PID, appended to the given string.
*/
- (void)addArgsForPid:(pid_t)pid toString:(NSMutableString *)str {
  size_t argsSizeEstimate = 0, argsSize = 0, index = 0;

  // Use stack space up to 128KiB.
  const size_t MAX_STACK_ALLOC = 128 * 1024;
  char *bytes = alloca(MAX_STACK_ALLOC);
  BOOL shouldFree = NO;

  int mib[] = {CTL_KERN, KERN_PROCARGS2, pid};

  // Get estimated length of arg array
  if (sysctl(mib, 3, NULL, &argsSizeEstimate, NULL, 0) < 0) return;
  argsSize = argsSizeEstimate + 512;

  // If this is larger than our allocated stack space, alloc from heap.
  if (argsSize > MAX_STACK_ALLOC) {
    bytes = malloc(argsSize);
    shouldFree = YES;
  }

  // Get the args. If this fails, free if necessary and return.
  if (sysctl(mib, 3, bytes, &argsSize, NULL, 0) != 0 || argsSize >= argsSizeEstimate + 512) {
    if (shouldFree) {
      free(bytes);
    }
    return;
  }

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
      ++replacedNulls;
      if (replacedNulls == argc) break;
      bytes[index] = ' ';
    }
  }

  // Potentially sanitize the args string.
  NSString *sanitized = [self sanitizeCString:&bytes[stringStart] ofLength:index - stringStart];
  if (sanitized) {
    [str appendFormat:@"|args=%@", sanitized];
  } else {
    [str appendFormat:@"|args=%s", &bytes[stringStart]];
  }

  if (shouldFree) {
    free(bytes);
  }
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
