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

#import "SNTDriverManager.h"

#import <IOKit/IODataQueueClient.h>
#import <IOKit/kext/KextManager.h>

#include <mach/mach_port.h>

#import "SNTLogging.h"

@interface SNTDriverManager ()
@property io_connect_t connection;
@end

@implementation SNTDriverManager

static const int MAX_DELAY = 15;

#pragma mark init/dealloc

- (instancetype)init {
  self = [super init];
  if (self) {
    kern_return_t kr;
    io_service_t serviceObject;
    CFDictionaryRef classToMatch;

    if (!(classToMatch = IOServiceMatching(USERCLIENT_CLASS))) {
      LOGD(@"Failed to create matching dictionary");
      return nil;
    }

    // Attempt to load driver. It may already be running, so ignore any return value.
    KextManagerLoadKextWithIdentifier(CFSTR(USERCLIENT_ID), NULL);

    // Locate driver. Wait for it if necessary.
    int delay = 1;
    do {
      CFRetain(classToMatch);  // this ref is released by IOServiceGetMatchingService
      serviceObject = IOServiceGetMatchingService(kIOMasterPortDefault, classToMatch);

      if (!serviceObject) {
        LOGD(@"Waiting for Santa driver to become available");
        sleep(delay);
        if (delay < MAX_DELAY) delay *= 2;
      }
    } while (!serviceObject);
    CFRelease(classToMatch);

    // This calls `initWithTask`, `attach` and `start` in `SantaDriverClient`
    kr = IOServiceOpen(serviceObject, mach_task_self(), 0, &_connection);
    IOObjectRelease(serviceObject);
    if (kr != kIOReturnSuccess) {
      LOGD(@"Failed to open Santa driver service");
      return nil;
    }

    // Call `open` in `SantaDriverClient`
    kr = IOConnectCallMethod(_connection, kSantaUserClientOpen, 0, 0, 0, 0, 0, 0, 0, 0);

    if (kr == kIOReturnExclusiveAccess) {
      LOGD(@"A client is already connected");
      return nil;
    } else if (kr != kIOReturnSuccess) {
      LOGD(@"An error occurred while opening the connection");
      return nil;
    }
  }
  return self;
}

- (void)dealloc {
  IOServiceClose(_connection);
}

#pragma mark Incoming messages

- (void)listenForDecisionRequests:(void (^)(santa_message_t))callback {
  [self listenForRequestsOfType:QUEUETYPE_DECISION withCallback:callback];
}

- (void)listenForLogRequests:(void (^)(santa_message_t))callback {
  [self listenForRequestsOfType:QUEUETYPE_LOG withCallback:callback];
}

- (void)listenForRequestsOfType:(santa_queuetype_t)type
                   withCallback:(void (^)(santa_message_t))callback {
  kern_return_t kr;

  // Allocate a mach port to receive notifactions from the IODataQueue
  mach_port_t receivePort = IODataQueueAllocateNotificationPort();
  if (receivePort == MACH_PORT_NULL) {
    LOGD(@"Failed to allocate notification port");
    return;
  }

  // This will call registerNotificationPort() inside our user client class
  kr = IOConnectSetNotificationPort(self.connection, type, receivePort, 0);
  if (kr != kIOReturnSuccess) {
    LOGD(@"Failed to register notification port for type %d: %d", type, kr);
    mach_port_destroy(mach_task_self(), receivePort);
    return;
  }

  // This will call clientMemoryForType() inside our user client class.
  mach_vm_address_t address = 0;
  mach_vm_size_t size = 0;
  kr = IOConnectMapMemory(self.connection, type, mach_task_self(), &address, &size, kIOMapAnywhere);
  if (kr != kIOReturnSuccess) {
    LOGD(@"Failed to map memory for type %d: %d", type, kr);
    mach_port_destroy(mach_task_self(), receivePort);
    return;
  }

  IODataQueueMemory *queueMemory = (IODataQueueMemory *)address;

  do {
    while (IODataQueueDataAvailable(queueMemory)) {
      santa_message_t vdata;
      uint32_t dataSize = sizeof(vdata);
      kr = IODataQueueDequeue(queueMemory, &vdata, &dataSize);
      if (kr == kIOReturnSuccess) {
        callback(vdata);
      } else {
        LOGE(@"Error dequeuing data for type %d: %d", type, kr);
        exit(2);
      }
    }
  } while (IODataQueueWaitForAvailableData(queueMemory, receivePort) == kIOReturnSuccess);

  IOConnectUnmapMemory(self.connection, type, mach_task_self(), address);
  mach_port_destroy(mach_task_self(), receivePort);
}

#pragma mark Outgoing messages

- (kern_return_t)postToKernelAction:(santa_action_t)action forVnodeID:(uint64_t)vnodeId {
  switch (action) {
    case ACTION_RESPOND_ALLOW:
      return IOConnectCallScalarMethod(_connection,
                                       kSantaUserClientAllowBinary,
                                       &vnodeId,
                                       1,
                                       0,
                                       0);
    case ACTION_RESPOND_DENY:
      return IOConnectCallScalarMethod(_connection,
                                       kSantaUserClientDenyBinary,
                                       &vnodeId,
                                       1,
                                       0,
                                       0);
    case ACTION_RESPOND_ACK:
      return IOConnectCallScalarMethod(_connection,
                                       kSantaUserClientAcknowledgeBinary,
                                       &vnodeId,
                                       1,
                                       0,
                                       0);
    default:
      return KERN_INVALID_ARGUMENT;
  }
}

- (NSArray<NSNumber *> *)cacheCounts {
  uint32_t input_count = 2;
  uint64_t cache_counts[2] = {0, 0};

  IOConnectCallScalarMethod(_connection,
                            kSantaUserClientCacheCount,
                            0,
                            0,
                            cache_counts,
                            &input_count);

  return @[ @(cache_counts[0]), @(cache_counts[1]) ];
}

- (BOOL)flushCacheNonRootOnly:(BOOL)nonRootOnly {
  const uint64_t nonRoot = nonRootOnly;
  return IOConnectCallScalarMethod(_connection,
                                   kSantaUserClientClearCache,
                                   &nonRoot,
                                   1,
                                   0,
                                   0) == KERN_SUCCESS;
}

- (santa_action_t)checkCache:(uint64_t)vnodeID {
  uint32_t input_count = 1;
  uint64_t vnode_action = 0;

  IOConnectCallScalarMethod(_connection,
                            kSantaUserClientCheckCache,
                            &vnodeID,
                            1,
                            &vnode_action,
                            &input_count);
  return (santa_action_t)vnode_action;
}

- (NSArray *)cacheBucketCount {
  santa_bucket_count_t counts = {};
  size_t size = sizeof(counts);

  NSMutableArray *a = [NSMutableArray array];

  do {
    IOConnectCallStructMethod(self.connection,
                              kSantaUserClientCacheBucketCount,
                              &counts,
                              size,
                              &counts,
                              &size);
    for (uint64_t i = 0; i < sizeof(counts.per_bucket) / sizeof(uint16_t); ++i) {
      [a addObject:@(counts.per_bucket[i])];
    }
  } while (counts.start > 0);

  return a;
}

@end
