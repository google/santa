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

#import "SNTEventLog.h"

#include <dlfcn.h>
#include <grp.h>
#include <pwd.h>
#include <sys/sysctl.h>

#import "SNTCachedDecision.h"

@interface SNTEventLog ()
@property NSMutableDictionary<NSNumber *, SNTCachedDecision *> *detailStore;
@property dispatch_queue_t detailStoreQueue;
@end

@implementation SNTEventLog

- (instancetype)init {
  self = [super init];
  if (self) {
    _detailStore = [NSMutableDictionary dictionaryWithCapacity:10000];
    _detailStoreQueue = dispatch_queue_create("com.google.santad.detail_store",
                                              DISPATCH_QUEUE_SERIAL);

    _userNameMap = [[NSCache alloc] init];
    _userNameMap.countLimit = 100;
    _groupNameMap = [[NSCache alloc] init];
    _groupNameMap.countLimit = 100;

    _dateFormatter = [[NSDateFormatter alloc] init];
    _dateFormatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    _dateFormatter.timeZone = [NSTimeZone timeZoneWithName:@"UTC"];
  }
  return self;
}

- (void)logDiskAppeared:(NSDictionary *)diskProperties {
  [self doesNotRecognizeSelector:_cmd];
}

- (void)logDiskDisappeared:(NSDictionary *)diskProperties {
  [self doesNotRecognizeSelector:_cmd];
}

- (void)logFileModification:(santa_message_t)message {
  [self doesNotRecognizeSelector:_cmd];
}

- (void)logDeniedExecution:(SNTCachedDecision *)cd withMessage:(santa_message_t)message {
  [self doesNotRecognizeSelector:_cmd];
}

- (void)logAllowedExecution:(santa_message_t)message {
  [self doesNotRecognizeSelector:_cmd];
}

- (void)logBundleHashingEvents:(NSArray<SNTStoredEvent *> *)events {
  [self doesNotRecognizeSelector:_cmd];
}

- (void)writeLog:(NSString *)log {
  [self doesNotRecognizeSelector:_cmd];
}

- (void)cacheDecision:(SNTCachedDecision *)cd {
  dispatch_sync(self.detailStoreQueue, ^{
    self.detailStore[@(cd.vnodeId)] = cd;
  });
}

- (SNTCachedDecision *)cachedDecisionForMessage:(santa_message_t)message {
  __block SNTCachedDecision *cd;
  dispatch_sync(self.detailStoreQueue, ^{
    cd = self.detailStore[@(message.vnode_id)];
  });
  return cd;
}

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

  if (length < 1) return @"";

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
    [str appendFormat:@"|args=%@", @(&bytes[stringStart])];
  }

  if (shouldFree) {
    free(bytes);
  }
}

- (NSString *)nameForUID:(uid_t)uid {
  NSNumber *uidNumber = @(uid);

  NSString *name = [self.userNameMap objectForKey:uidNumber];
  if (name) return name;

  struct passwd *pw = getpwuid(uid);
  if (pw) {
    name = @(pw->pw_name);
    [self.userNameMap setObject:name forKey:uidNumber];
  }
  return name;
}

- (NSString *)nameForGID:(gid_t)gid {
  NSNumber *gidNumber = @(gid);

  NSString *name = [self.groupNameMap objectForKey:gidNumber];
  if (name) return name;

  struct group *gr = getgrgid(gid);
  if (gr) {
    name = @(gr->gr_name);
    [self.groupNameMap setObject:name forKey:gidNumber];
  }
  return name;
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

/**
 Uses the executable path, uid, and gid from a given santa_message_t to determine if the path
 has been translocated by GateKeeper and if so, returns the original path of the executable.  This
 requires macOS 10.12 or higher.  We use dlopen to access the functions we need in
 Security.framework so that we can still build against the 10.11 SDK.  If the path has not been
 translocated or if running on macOS prior to 10.12, this method returns nil.
 */
- (NSString *)originalPathForTranslocation:(santa_message_t)message {
  // The first time this function is called, we attempt to find the addresses of
  // SecTranslocateIsTranslocatedURL and SecTranslocateCreateOriginalPathForURL inside of the
  // Security.framework library.  If we were successful, handle will be non-NULL and is never
  // closed.
  static Boolean (*IsTranslocatedURL)(CFURLRef, bool *, CFErrorRef *) = NULL;
  static CFURLRef __nullable (*CreateOriginalPathForURL)(CFURLRef, CFErrorRef *) = NULL;
  static dispatch_once_t token;
  dispatch_once(&token, ^{
    void *handle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (handle) {
      IsTranslocatedURL = dlsym(handle, "SecTranslocateIsTranslocatedURL");
      CreateOriginalPathForURL = dlsym(handle, "SecTranslocateCreateOriginalPathForURL");
      if (!IsTranslocatedURL || !CreateOriginalPathForURL) {
        IsTranslocatedURL = NULL;
        CreateOriginalPathForURL = NULL;
        dlclose(handle);
      }
    }
  });

  // If we couldn't open the library or find the functions we need, don't do anything.
  if (!IsTranslocatedURL || !CreateOriginalPathForURL) return nil;

  // Determine if the executable URL has been translocated or not.
  CFURLRef cfExecURL = (__bridge CFURLRef)[NSURL fileURLWithPath:@(message.path)];
  bool isTranslocated = false;
  if (!IsTranslocatedURL(cfExecURL, &isTranslocated, NULL) || !isTranslocated) return nil;

  // SecTranslocateCreateOriginalPathForURL requires that our uid be the same as the user who
  // launched the executable.  So we temporarily drop from root down to this uid, then reset.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated"
  pthread_setugid_np(message.uid, message.gid);
  NSURL *origURL = CFBridgingRelease(CreateOriginalPathForURL(cfExecURL, NULL));
  pthread_setugid_np(KAUTH_UID_NONE, KAUTH_GID_NONE);
#pragma clang diagnostic pop

  return [origURL path];  // this will be nil if there was an error
}

@end
