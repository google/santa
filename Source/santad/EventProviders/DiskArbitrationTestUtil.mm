/// Copyright 2021 Google Inc. All rights reserved.
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

#include <stdlib.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/ucred.h>

#import "Source/santad/EventProviders/DiskArbitrationTestUtil.h"

NS_ASSUME_NONNULL_BEGIN

@implementation MockDADisk
@end

@implementation MockDiskArbitration

- (instancetype _Nonnull)init {
  self = [super init];
  if (self) {
    _insertedDevices = [NSMutableDictionary dictionary];
    _diskAppearedCallbacks = [NSMutableArray array];
  }
  return self;
}

- (void)reset {
  [self.insertedDevices removeAllObjects];
  [self.diskAppearedCallbacks removeAllObjects];
  self.sessionQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
}

- (void)insert:(MockDADisk *)ref {
  if (!ref.diskDescription[@"DAMediaBSDName"]) {
    [NSException raise:@"Missing DAMediaBSDName"
                format:@"The MockDADisk is missing the DAMediaBSDName diskDescription key."];
  }
  self.insertedDevices[ref.diskDescription[@"DAMediaBSDName"]] = ref;

  for (MockDADiskAppearedCallback callback in self.diskAppearedCallbacks) {
    dispatch_sync(self.sessionQueue, ^{
      callback((__bridge DADiskRef)ref);
    });
  }
}

// Retrieve an initialized singleton MockDiskArbitration object
+ (instancetype _Nonnull)mockDiskArbitration {
  static MockDiskArbitration *sharedES;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedES = [[MockDiskArbitration alloc] init];
  });
  return sharedES;
};

@end

@implementation MockStatfs
- (instancetype _Nonnull)initFrom:(NSString *)from on:(NSString *)on flags:(NSNumber *)flags {
  self = [super init];
  if (self) {
    _fromName = from;
    _onName = on;
    _flags = flags;
  }
  return self;
}
@end

@implementation MockMounts

- (instancetype _Nonnull)init {
  self = [super init];
  if (self) {
    _mounts = [NSMutableDictionary dictionary];
  }
  return self;
}

- (void)reset {
  [self.mounts removeAllObjects];
}

- (void)insert:(MockStatfs *)sfs {
  self.mounts[sfs.fromName] = sfs;
}

+ (instancetype _Nonnull)mockMounts {
  static MockMounts *sharedMounts;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedMounts = [[MockMounts alloc] init];
  });
  return sharedMounts;
}

@end

void DADiskMountWithArguments(DADiskRef _Nonnull disk, CFURLRef __nullable path,
                              DADiskMountOptions options, DADiskMountCallback __nullable callback,
                              void *__nullable context,
                              CFStringRef __nullable arguments[_Nullable]) {
  MockDADisk *mockDisk = (__bridge MockDADisk *)disk;
  mockDisk.wasMounted = YES;

  if (context) {
    dispatch_semaphore_t sema = (__bridge dispatch_semaphore_t)context;
    dispatch_semaphore_signal(sema);
  }
}

DADiskRef __nullable DADiskCreateFromBSDName(CFAllocatorRef __nullable allocator,
                                             DASessionRef session, const char *name) {
  NSString *nsName = [NSString stringWithUTF8String:name];

  MockDiskArbitration *mockDA = [MockDiskArbitration mockDiskArbitration];
  MockDADisk *got = mockDA.insertedDevices[nsName];
  DADiskRef ref = (__bridge DADiskRef)got;
  CFRetain(ref);
  return ref;
}

CFDictionaryRef __nullable DADiskCopyDescription(DADiskRef disk) {
  CFDictionaryRef description = NULL;
  if (disk) {
    MockDADisk *mockDisk = (__bridge MockDADisk *)disk;
    description = (__bridge_retained CFDictionaryRef)mockDisk.diskDescription;
  }
  return description;
}

void DARegisterDiskAppearedCallback(DASessionRef session, CFDictionaryRef __nullable match,
                                    DADiskAppearedCallback callback, void *__nullable context) {
  MockDiskArbitration *mockDA = [MockDiskArbitration mockDiskArbitration];
  [mockDA.diskAppearedCallbacks addObject:^(DADiskRef ref) {
    callback(ref, context);
  }];
}

void DARegisterDiskDisappearedCallback(DASessionRef session, CFDictionaryRef __nullable match,
                                       DADiskDisappearedCallback callback,
                                       void *__nullable context) {};

void DARegisterDiskDescriptionChangedCallback(DASessionRef session,
                                              CFDictionaryRef __nullable match,
                                              CFArrayRef __nullable watch,
                                              DADiskDescriptionChangedCallback callback,
                                              void *__nullable context) {};

void DASessionSetDispatchQueue(DASessionRef session, dispatch_queue_t __nullable queue) {
  MockDiskArbitration *mockDA = [MockDiskArbitration mockDiskArbitration];
  mockDA.sessionQueue = queue;
};

DASessionRef __nullable DASessionCreate(CFAllocatorRef __nullable allocator) {
  return (__bridge DASessionRef)[MockDiskArbitration mockDiskArbitration];
};

void DADiskUnmount(DADiskRef disk, DADiskUnmountOptions options,
                   DADiskUnmountCallback __nullable callback, void *__nullable context) {
  MockDADisk *mockDisk = (__bridge MockDADisk *)disk;
  mockDisk.wasUnmounted = YES;

  dispatch_semaphore_t sema = (__bridge dispatch_semaphore_t)context;
  dispatch_semaphore_signal(sema);
}

int getmntinfo_r_np(struct statfs *__nullable *__nullable mntbufp, int flags) {
  MockMounts *mockMounts = [MockMounts mockMounts];

  struct statfs *sfs = (struct statfs *)calloc(mockMounts.mounts.count, sizeof(struct statfs));

  __block NSUInteger i = 0;
  [mockMounts.mounts
    enumerateKeysAndObjectsUsingBlock:^(NSString *key, MockStatfs *mockSfs, BOOL *stop) {
      strlcpy(sfs[i].f_mntfromname, mockSfs.fromName.UTF8String, sizeof(sfs[i].f_mntfromname));
      strlcpy(sfs[i].f_mntonname, mockSfs.onName.UTF8String, sizeof(sfs[i].f_mntonname));
      sfs[i].f_flags = [mockSfs.flags unsignedIntValue];
      i++;
    }];

  *mntbufp = sfs;

  return (int)mockMounts.mounts.count;
}

NS_ASSUME_NONNULL_END
