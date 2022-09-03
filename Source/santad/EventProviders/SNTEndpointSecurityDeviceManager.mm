/// Copyright 2022 Google Inc. All rights reserved.
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
#import "Source/santad/EventProviders/SNTEndpointSecurityDeviceManager.h"

#import <DiskArbitration/DiskArbitration.h>
#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>

#include <atomic>
#include <memory>

#include <bsm/libbsm.h>
#include <errno.h>
#include <libproc.h>
#include <sys/mount.h>

#import "Source/common/SNTDeviceEvent.h"
#import "Source/common/SNTLogging.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

using santa::santad::event_providers::AuthResultCache;
using santa::santad::event_providers::FlushCacheMode;
using santa::santad::event_providers::endpoint_security::EndpointSecurityAPI;
using santa::santad::event_providers::endpoint_security::Message;
using santa::santad::logs::endpoint_security::Logger;

@interface SNTEndpointSecurityDeviceManager ()

- (void)logDiskAppeared:(NSDictionary *)props;
- (void)logDiskDisappeared:(NSDictionary *)props;

@property DASessionRef diskArbSession;
@property(nonatomic, readonly) dispatch_queue_t diskQueue;

@end

void diskMountedCallback(DADiskRef disk, DADissenterRef dissenter, void *context) {
  if (dissenter) {
    DAReturn status = DADissenterGetStatus(dissenter);

    NSString *statusString = (NSString *)DADissenterGetStatusString(dissenter);
    IOReturn systemCode = err_get_system(status);
    IOReturn subSystemCode = err_get_sub(status);
    IOReturn errorCode = err_get_code(status);

    LOGE(@"SNTEndpointSecurityDeviceManager: dissenter status codes: system: %d, subsystem: %d, "
         @"err: %d; status: %s",
         systemCode, subSystemCode, errorCode, [statusString UTF8String]);
  }
}

void diskAppearedCallback(DADiskRef disk, void *context) {
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;
  SNTEndpointSecurityDeviceManager *dm = (__bridge SNTEndpointSecurityDeviceManager *)context;

  [dm logDiskAppeared:props];
}

void diskDescriptionChangedCallback(DADiskRef disk, CFArrayRef keys, void *context) {
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;

  if (props[@"DAVolumePath"]) {
    SNTEndpointSecurityDeviceManager *dm = (__bridge SNTEndpointSecurityDeviceManager *)context;

    [dm logDiskAppeared:props];
  }
}

void diskDisappearedCallback(DADiskRef disk, void *context) {
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;

  SNTEndpointSecurityDeviceManager *dm = (__bridge SNTEndpointSecurityDeviceManager *)context;

  [dm logDiskDisappeared:props];
}

NSArray<NSString *> *maskToMountArgs(long remountOpts) {
  NSMutableArray<NSString *> *args = [NSMutableArray array];
  if (remountOpts & MNT_RDONLY) [args addObject:@"rdonly"];
  if (remountOpts & MNT_NOEXEC) [args addObject:@"noexec"];
  if (remountOpts & MNT_NOSUID) [args addObject:@"nosuid"];
  if (remountOpts & MNT_DONTBROWSE) [args addObject:@"nobrowse"];
  if (remountOpts & MNT_UNKNOWNPERMISSIONS) [args addObject:@"noowners"];
  if (remountOpts & MNT_NODEV) [args addObject:@"nodev"];
  if (remountOpts & MNT_JOURNALED) [args addObject:@"-j"];
  if (remountOpts & MNT_ASYNC) [args addObject:@"async"];
  return args;
}

long mountArgsToMask(NSArray<NSString *> *args) {
  long flags = 0;
  for (NSString *i in args) {
    NSString *arg = [i lowercaseString];
    if ([arg isEqualToString:@"rdonly"])
      flags |= MNT_RDONLY;
    else if ([arg isEqualToString:@"noexec"])
      flags |= MNT_NOEXEC;
    else if ([arg isEqualToString:@"nosuid"])
      flags |= MNT_NOSUID;
    else if ([arg isEqualToString:@"nobrowse"])
      flags |= MNT_DONTBROWSE;
    else if ([arg isEqualToString:@"noowners"])
      flags |= MNT_UNKNOWNPERMISSIONS;
    else if ([arg isEqualToString:@"nodev"])
      flags |= MNT_NODEV;
    else if ([arg isEqualToString:@"-j"])
      flags |= MNT_JOURNALED;
    else if ([arg isEqualToString:@"async"])
      flags |= MNT_ASYNC;
    else
      LOGE(@"SNTEndpointSecurityDeviceManager: unexpected mount arg: %@", arg);
  }
  return flags;
}

NS_ASSUME_NONNULL_BEGIN

@implementation SNTEndpointSecurityDeviceManager {
  std::shared_ptr<AuthResultCache> _authResultCache;
  std::shared_ptr<Logger> _logger;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                       logger:(std::shared_ptr<Logger>)logger
              authResultCache:(std::shared_ptr<AuthResultCache>)authResultCache {
  self = [super initWithESAPI:std::move(esApi)];
  if (self) {
    _logger = logger;
    _blockUSBMount = false;

    _diskQueue = dispatch_queue_create("com.google.santad.disk_queue", DISPATCH_QUEUE_SERIAL);

    _diskArbSession = DASessionCreate(NULL);
    DASessionSetDispatchQueue(_diskArbSession, _diskQueue);

    [self establishClientOrDie];
  }
  return self;
}

- (void)logDiskAppeared:(NSDictionary *)props {
  self->_logger->LogDiskAppeared(props);
}

- (void)logDiskDisappeared:(NSDictionary *)props {
  self->_logger->LogDiskDisappeared(props);
}

- (void)handleMessage:(Message &&)esMsg {
  if (!self.blockUSBMount) {
    // TODO: We should also unsubscribe from events when this isn't set, but
    // this is generally a low-volume event type.
    [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_ALLOW cacheable:false];
    return;
  }

  if (esMsg->event_type == ES_EVENT_TYPE_NOTIFY_UNMOUNT) {
    self->_authResultCache->FlushCache(FlushCacheMode::kNonRootOnly);
    return;
  }

  [self processMessage:std::move(esMsg)
               handler:^(const Message &msg) {
                 es_auth_result_t result = [self handleAuthMount:msg];
                 [self respondToMessage:msg withAuthResult:result cacheable:false];
               }];
}

- (void)enable {
  DARegisterDiskAppearedCallback(_diskArbSession, NULL, diskAppearedCallback,
                                 (__bridge void *)self);
  DARegisterDiskDescriptionChangedCallback(_diskArbSession, NULL, NULL,
                                           diskDescriptionChangedCallback, (__bridge void *)self);
  DARegisterDiskDisappearedCallback(_diskArbSession, NULL, diskDisappearedCallback,
                                    (__bridge void *)self);

  [super subscribeAndClearCache:{
                                  ES_EVENT_TYPE_AUTH_MOUNT,
                                  ES_EVENT_TYPE_AUTH_REMOUNT,
                                  ES_EVENT_TYPE_NOTIFY_UNMOUNT,
                                }];
}

- (es_auth_result_t)handleAuthMount:(const Message &)m {
  struct statfs *eventStatFS;

  switch (m->event_type) {
    case ES_EVENT_TYPE_AUTH_MOUNT: eventStatFS = m->event.mount.statfs; break;
    case ES_EVENT_TYPE_AUTH_REMOUNT: eventStatFS = m->event.remount.statfs; break;
    default:
      // This is a programming error
      LOGE(@"Unexpected Event Type passed to DeviceManager handleAuthMount: %d", m->event_type);
      exit(EXIT_FAILURE);
  }

  long mountMode = eventStatFS->f_flags;
  pid_t pid = audit_token_to_pid(m->process->audit_token);
  LOGD(
    @"SNTEndpointSecurityDeviceManager: mount syscall arriving from path: %s, pid: %d, fflags: %lu",
    m->process->executable->path.data, pid, mountMode);

  DADiskRef disk = DADiskCreateFromBSDName(NULL, self.diskArbSession, eventStatFS->f_mntfromname);
  CFAutorelease(disk);

  // TODO(tnek): Log all of the other attributes available in diskInfo into a structured log format.
  NSDictionary *diskInfo = CFBridgingRelease(DADiskCopyDescription(disk));
  BOOL isInternal = [diskInfo[(__bridge NSString *)kDADiskDescriptionDeviceInternalKey] boolValue];
  BOOL isRemovable = [diskInfo[(__bridge NSString *)kDADiskDescriptionMediaRemovableKey] boolValue];
  BOOL isEjectable = [diskInfo[(__bridge NSString *)kDADiskDescriptionMediaEjectableKey] boolValue];
  NSString *protocol = diskInfo[(__bridge NSString *)kDADiskDescriptionDeviceProtocolKey];
  BOOL isUSB = [protocol isEqualToString:@"USB"];
  BOOL isVirtual = [protocol isEqualToString:@"Virtual Interface"];

  NSString *kind = diskInfo[(__bridge NSString *)kDADiskDescriptionMediaKindKey];

  // TODO: check kind and protocol for banned things (e.g. MTP).
  LOGD(@"SNTEndpointSecurityDeviceManager: DiskInfo Protocol: %@ Kind: %@ isInternal: %d "
       @"isRemovable: %d "
       @"isEjectable: %d",
       protocol, kind, isInternal, isRemovable, isEjectable);

  // If the device is internal or virtual we are okay with the operation. We
  // also are okay with operations for devices that are non-removal as long as
  // they are NOT a USB device.
  if (isInternal || isVirtual || (!isRemovable && !isEjectable && !isUSB)) {
    return ES_AUTH_RESULT_ALLOW;
  }

  SNTDeviceEvent *event = [[SNTDeviceEvent alloc]
    initWithOnName:[NSString stringWithUTF8String:eventStatFS->f_mntonname]
          fromName:[NSString stringWithUTF8String:eventStatFS->f_mntfromname]];

  BOOL shouldRemount = self.remountArgs != nil && [self.remountArgs count] > 0;

  if (shouldRemount) {
    event.remountArgs = self.remountArgs;
    long remountOpts = mountArgsToMask(self.remountArgs);

    LOGD(@"SNTEndpointSecurityDeviceManager: mountMode: %@", maskToMountArgs(mountMode));
    LOGD(@"SNTEndpointSecurityDeviceManager: remountOpts: %@", maskToMountArgs(remountOpts));

    if ((mountMode & remountOpts) == remountOpts && m->event_type != ES_EVENT_TYPE_AUTH_REMOUNT) {
      LOGD(@"SNTEndpointSecurityDeviceManager: Allowing as mount as flags match remountOpts");
      return ES_AUTH_RESULT_ALLOW;
    }

    long newMode = mountMode | remountOpts;
    LOGI(@"SNTEndpointSecurityDeviceManager: remounting device '%s'->'%s', flags (%lu) -> (%lu)",
         eventStatFS->f_mntfromname, eventStatFS->f_mntonname, mountMode, newMode);
    [self remount:disk mountMode:newMode];
  }

  if (self.deviceBlockCallback) {
    self.deviceBlockCallback(event);
  }

  return ES_AUTH_RESULT_DENY;
}

- (void)remount:(DADiskRef)disk mountMode:(long)remountMask {
  NSArray<NSString *> *args = maskToMountArgs(remountMask);
  CFStringRef *argv = (CFStringRef *)calloc(args.count + 1, sizeof(CFStringRef));
  CFArrayGetValues((__bridge CFArrayRef)args, CFRangeMake(0, (CFIndex)args.count),
                   (const void **)argv);

  DADiskMountWithArguments(disk, NULL, kDADiskMountOptionDefault, diskMountedCallback,
                           (__bridge void *)self, (CFStringRef *)argv);

  free(argv);
}

@end

NS_ASSUME_NONNULL_END
