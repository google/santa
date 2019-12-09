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

#import "Source/santad/EventProviders/SNTDriverManager.h"

#import <IOKit/IODataQueueClient.h>
#import <IOKit/kext/KextManager.h>

#include <mach/mach_port.h>

#import "Source/common/SNTLogging.h"

@interface SNTDriverManager ()
@property io_connect_t connection;
@property(readwrite) BOOL connectionEstablished;
@property(nonatomic, readonly) dispatch_queue_t dmAuthQueue;
@property(nonatomic, readonly) dispatch_queue_t dmNotifiyQueue;
@end

@implementation SNTDriverManager

#pragma mark init/dealloc

- (instancetype)init {
  self = [super init];
  if (self) {
    _dmAuthQueue =
        dispatch_queue_create("com.google.santa.daemon.dm_auth", DISPATCH_QUEUE_CONCURRENT);
    dispatch_set_target_queue(_dmAuthQueue,
                              dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0));
    _dmNotifiyQueue =
        dispatch_queue_create("com.google.santa.daemon.dm_notify", DISPATCH_QUEUE_CONCURRENT);
    dispatch_set_target_queue(_dmNotifiyQueue, dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0));

    CFDictionaryRef classToMatch = IOServiceMatching(USERCLIENT_CLASS);
    if (!classToMatch) {
      LOGE(@"Failed to create matching dictionary");
      return nil;
    }

    // Attempt to load driver. It may already be running, so ignore any return value.
    KextManagerLoadKextWithIdentifier(CFSTR(USERCLIENT_ID), NULL);

    // Wait for the driver to appear
    [self waitForDriver:classToMatch];
  }
  return self;
}

- (void)dealloc {
  IOServiceClose(_connection);
}

#pragma mark Driver Waiting

// Helper function used with IOServiceAddMatchingNotification which expects
// a DriverAppearedBlock to be passed as the 'reference' argument. The block
// will be called for each object iterated over and if the block wants to keep
// the object, it should call IOObjectRetain().
typedef void (^DriverAppearedBlock)(io_object_t object);
static void driverAppearedHandler(void *info, io_iterator_t iterator) {
  DriverAppearedBlock block = (__bridge DriverAppearedBlock)info;
  if (!block) return;
  io_object_t object = 0;
  while ((object = IOIteratorNext(iterator))) {
    block(object);
    IOObjectRelease(object);
  }
}

// Wait for the driver to appear, then attach to and open it.
- (void)waitForDriver:(CFDictionaryRef CF_RELEASES_ARGUMENT)matchingDict {
  IONotificationPortRef notificationPort = IONotificationPortCreate(kIOMasterPortDefault);
  CFRunLoopAddSource([[NSRunLoop currentRunLoop] getCFRunLoop],
                     IONotificationPortGetRunLoopSource(notificationPort),
                     kCFRunLoopDefaultMode);

  io_iterator_t iterator = 0;

  DriverAppearedBlock block = ^(io_object_t object) {
    // This calls `initWithTask`, `attach` and `start` in `SantaDriverClient`
    kern_return_t kr = IOServiceOpen(object, mach_task_self(), 0, &self->_connection);
    if (kr != kIOReturnSuccess) {
      LOGE(@"Failed to open santa-driver service: 0x%X", kr);
      exit(1);
    }

    // Call `open` in `SantaDriverClient`
    kr = IOConnectCallMethod(self->_connection, kSantaUserClientOpen, 0, 0, 0, 0, 0, 0, 0, 0);
    if (kr == kIOReturnExclusiveAccess) {
      LOGE(@"A client is already connected");
      exit(2);
    } else if (kr != kIOReturnSuccess) {
      LOGE(@"An error occurred while opening the connection: 0x%X", kr);
      exit(3);
    }

    // Release the iterator to disarm the notifications.
    IOObjectRelease(iterator);
    IONotificationPortDestroy(notificationPort);

    self->_connectionEstablished = YES;
  };

  LOGI(@"Waiting for Santa driver to become available");

  IOServiceAddMatchingNotification(notificationPort,
                                   kIOMatchedNotification,
                                   matchingDict,
                                   driverAppearedHandler,
                                   (__bridge_retained void *)block,
                                   &iterator);

  // Call the handler once to 'empty' the iterator, arming it. If the driver is already loaded
  // this will immediately cause the connection to be fully established.
  driverAppearedHandler((__bridge_retained void*)block, iterator);
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
  while (!self.connectionEstablished) usleep(100000); // 100ms

  // Allocate a mach port to receive notifactions from the IODataQueue
  mach_port_t receivePort = IODataQueueAllocateNotificationPort();
  if (receivePort == MACH_PORT_NULL) {
    LOGD(@"Failed to allocate notification port");
    return;
  }

  // This will call registerNotificationPort() inside our user client class
  kern_return_t kr = IOConnectSetNotificationPort(self.connection, type, receivePort, 0);
  if (kr != kIOReturnSuccess) {
    LOGD(@"Failed to register notification port for type %d: 0x%X", type, kr);
    mach_port_destroy(mach_task_self(), receivePort);
    return;
  }

  // This will call clientMemoryForType() inside our user client class.
  mach_vm_address_t address = 0;
  mach_vm_size_t size = 0;
  kr = IOConnectMapMemory(self.connection, type, mach_task_self(), &address, &size, kIOMapAnywhere);
  if (kr != kIOReturnSuccess) {
    LOGD(@"Failed to map memory for type %d: 0x%X", type, kr);
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
        switch (type) {
          case QUEUETYPE_DECISION: {
            dispatch_async(self.dmAuthQueue, ^{
              callback(vdata);
            });
            break;
          }
          case QUEUETYPE_LOG: {
            dispatch_async(self.dmNotifiyQueue, ^{
              callback(vdata);
            });
            break;
          }
          default: {
            break;
          }
        }
      } else {
        LOGE(@"Error dequeuing data for type %d: 0x%X", type, kr);
        exit(2);
      }
    }
  } while (IODataQueueWaitForAvailableData(queueMemory, receivePort) == kIOReturnSuccess);

  IOConnectUnmapMemory(self.connection, type, mach_task_self(), address);
  mach_port_destroy(mach_task_self(), receivePort);
}

#pragma mark Outgoing messages

- (kern_return_t)postAction:(santa_action_t)action forMessage:(santa_message_t)sm {
  santa_vnode_id_t vnodeId = sm.vnode_id;
  switch (action) {
    case ACTION_RESPOND_ALLOW:
      return IOConnectCallStructMethod(_connection,
                                       kSantaUserClientAllowBinary,
                                       &vnodeId,
                                       sizeof(vnodeId),
                                       0,
                                       0);
    case ACTION_RESPOND_DENY:
      return IOConnectCallStructMethod(_connection,
                                       kSantaUserClientDenyBinary,
                                       &vnodeId,
                                       sizeof(vnodeId),
                                       0,
                                       0);
    case ACTION_RESPOND_ACK:
      return IOConnectCallStructMethod(_connection,
                                       kSantaUserClientAcknowledgeBinary,
                                       &vnodeId,
                                       sizeof(vnodeId),
                                       0,
                                       0);
    case ACTION_RESPOND_ALLOW_COMPILER:
      return IOConnectCallStructMethod(_connection,
                                       kSantaUserClientAllowCompiler,
                                       &vnodeId,
                                       sizeof(vnodeId),
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

- (kern_return_t)removeCacheEntryForVnodeID:(santa_vnode_id_t)vnodeId {
  return IOConnectCallStructMethod(_connection,
                                   kSantaUserClientRemoveCacheEntry,
                                   &vnodeId,
                                   sizeof(vnodeId),
                                   0,
                                   0);
}

- (santa_action_t)checkCache:(santa_vnode_id_t)vnodeID {
  uint64_t output;
  uint32_t outputCnt = 1;

  IOConnectCallMethod(self.connection, kSantaUserClientCheckCache,
                      NULL, 0, &vnodeID, sizeof(santa_vnode_id_t),
                      &output, &outputCnt, NULL, 0);
  return (santa_action_t)output;
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

- (void)fileModificationPrefixFilterAdd:(NSArray *)filters {
  uint64_t n = 0;
  uint32_t n_len = 1;

  for (NSString *filter in filters) {
    char buffer[MAXPATHLEN];
    if (![filter getFileSystemRepresentation:buffer maxLength:MAXPATHLEN]) {
      LOGE(@"Invalid filemod prefix filter: %@", filter);
      continue;
    }

    kern_return_t ret = IOConnectCallMethod(self.connection, kSantaUserClientFilemodPrefixFilterAdd,
                                            NULL, 0, buffer, sizeof(const char[MAXPATHLEN]),
                                            &n, &n_len, NULL, NULL);

    if (ret != kIOReturnSuccess) {
      LOGE(@"Failed to add prefix filter: %s error: 0x%x", buffer, ret);

      // If the tree is full, stop.
      // TODO(bur): Maybe continue here with some smarts around the size? Shorter, not yet iterated
      //            prefixes (that may fit) are ignored. Seems worth it not to spam the driver.
      if (ret == kIOReturnNoResources) {
        LOGE(@"Prefix filter tree is full!");
        return;
      }
    }
  }
}

- (void)fileModificationPrefixFilterReset {
  IOConnectCallScalarMethod(self.connection, kSantaUserClientFilemodPrefixFilterReset,
                            NULL, 0, NULL, NULL);
}

@end
