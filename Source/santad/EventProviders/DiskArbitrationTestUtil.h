/// Copyright 2021-2022 Google Inc. All rights reserved.
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

#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>
#include <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Mock object to point the opaque DADiskRefs to instead.
// Note that this will have undefined behavior for DA functions that aren't
// shimmed out by this utility, as the original DADiskRef refers to a completely
// different struct managed by the CFRuntime.
// https://opensource.apple.com/source/DiskArbitration/DiskArbitration-297.70.1/DiskArbitration/DADisk.c.auto.html
@interface MockDADisk : NSObject
@property(nonatomic) NSDictionary *diskDescription;
@property(nonatomic, readwrite) NSString *name;
@end

typedef void (^MockDADiskAppearedCallback)(DADiskRef ref);
// Singleton mock fixture around all of the DiskArbitration framework functions
@interface MockDiskArbitration : NSObject
@property(nonatomic, readwrite, nonnull)
  NSMutableDictionary<NSString *, MockDADisk *> *insertedDevices;
@property(nonatomic, readwrite, nonnull)
  NSMutableArray<MockDADiskAppearedCallback> *diskAppearedCallbacks;
@property(nonatomic) BOOL wasRemounted;
@property(nonatomic, nullable) dispatch_queue_t sessionQueue;

- (instancetype _Nonnull)init;
- (void)reset;

// Also triggers DADiskRegisterDiskAppearedCallback
- (void)insert:(MockDADisk *)ref bsdName:(NSString *)bsdName;

// Retrieve an initialized singleton MockDiskArbitration object
+ (instancetype _Nonnull)mockDiskArbitration;
@end

//
// All DiskArbitration functions used in SNTEndpointSecurityDeviceManager
// and shimmed out accordingly.
//
CF_EXTERN_C_BEGIN

void DADiskMountWithArguments(DADiskRef _Nonnull disk, CFURLRef __nullable path,
                              DADiskMountOptions options, DADiskMountCallback __nullable callback,
                              void *__nullable context,
                              CFStringRef __nullable arguments[_Nullable]);

DADiskRef __nullable DADiskCreateFromBSDName(CFAllocatorRef __nullable allocator,
                                             DASessionRef session, const char *name);

CFDictionaryRef __nullable DADiskCopyDescription(DADiskRef disk);

void DARegisterDiskAppearedCallback(DASessionRef session, CFDictionaryRef __nullable match,
                                    DADiskAppearedCallback callback, void *__nullable context);

void DARegisterDiskDisappearedCallback(DASessionRef session, CFDictionaryRef __nullable match,
                                       DADiskDisappearedCallback callback,
                                       void *__nullable context);

void DARegisterDiskDescriptionChangedCallback(DASessionRef session,
                                              CFDictionaryRef __nullable match,
                                              CFArrayRef __nullable watch,
                                              DADiskDescriptionChangedCallback callback,
                                              void *__nullable context);

void DASessionSetDispatchQueue(DASessionRef session, dispatch_queue_t __nullable queue);
DASessionRef __nullable DASessionCreate(CFAllocatorRef __nullable allocator);

CF_EXTERN_C_END
NS_ASSUME_NONNULL_END
