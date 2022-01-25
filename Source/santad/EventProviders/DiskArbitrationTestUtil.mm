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
  self.wasRemounted = NO;
}

- (void)insert:(MockDADisk *)ref bsdName:(NSString *)bsdName {
  self.insertedDevices[bsdName] = ref;

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

void DADiskMountWithArguments(DADiskRef _Nonnull disk, CFURLRef __nullable path,
                              DADiskMountOptions options, DADiskMountCallback __nullable callback,
                              void *__nullable context,
                              CFStringRef __nullable arguments[_Nullable]) {
  MockDiskArbitration *mockDA = [MockDiskArbitration mockDiskArbitration];
  mockDA.wasRemounted = YES;
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
                                       void *__nullable context){};

void DARegisterDiskDescriptionChangedCallback(DASessionRef session,
                                              CFDictionaryRef __nullable match,
                                              CFArrayRef __nullable watch,
                                              DADiskDescriptionChangedCallback callback,
                                              void *__nullable context){};

void DASessionSetDispatchQueue(DASessionRef session, dispatch_queue_t __nullable queue) {
  MockDiskArbitration *mockDA = [MockDiskArbitration mockDiskArbitration];
  mockDA.sessionQueue = queue;
};

DASessionRef __nullable DASessionCreate(CFAllocatorRef __nullable allocator) {
  return (__bridge DASessionRef)[MockDiskArbitration mockDiskArbitration];
};

NS_ASSUME_NONNULL_END
