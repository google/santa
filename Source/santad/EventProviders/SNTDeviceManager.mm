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
#import "Source/santad/EventProviders/SNTDeviceManager.h"

#import <DiskArbitration/DiskArbitration.h>
#import <Foundation/Foundation.h>

#include <bsm/libbsm.h>
#include <errno.h>
#include <libproc.h>
#include <sys/mount.h>
#include <atomic>
#include <memory>

#import "Source/common/SNTLogging.h"
#import "Source/santad/Logs/SNTEventLog.h"

void diskMountedCallback(DADiskRef disk, DADissenterRef dissenter, void *context) {
  if (dissenter) {
    DAReturn status = DADissenterGetStatus(dissenter);

    NSString *statusString = (NSString *)DADissenterGetStatusString(dissenter);
    IOReturn systemCode = err_get_system(status);
    IOReturn subSystemCode = err_get_sub(status);
    IOReturn errorCode = err_get_code(status);

    LOGE(
      @"SNTDeviceManager: dissenter status codes: system: %d, subsystem: %d, err: %d; status: %s",
      systemCode, subSystemCode, errorCode, [statusString UTF8String]);
  }
}

void diskAppearedCallback(DADiskRef disk, void *context) {
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;
  [[SNTEventLog logger] logDiskAppeared:props];
}

void diskDescriptionChangedCallback(DADiskRef disk, CFArrayRef keys, void *context) {
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;

  if (props[@"DAVolumePath"]) {
    [[SNTEventLog logger] logDiskAppeared:props];
  }
}

void diskDisappearedCallback(DADiskRef disk, void *context) {
  SNTDeviceManager *app = (__bridge SNTDeviceManager *)context;
  NSDictionary *props = CFBridgingRelease(DADiskCopyDescription(disk));
  if (![props[@"DAVolumeMountable"] boolValue]) return;

  [[SNTEventLog logger] logDiskDisappeared:props];
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
  for (NSString *arg in args) {
    arg = [arg lowercaseString];
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
  }
  return flags;
}

@interface SNTDeviceManager ()

@property DASessionRef diskArbSession;
@property(readonly, nonatomic) es_client_t *client;
@property(nonatomic, readonly) dispatch_queue_t esAuthQueue;
@end

@implementation SNTDeviceManager

- (instancetype)init API_AVAILABLE(macos(10.15)) {
  self = [super init];
  if (self) {
    _blockUSBMount = false;

    dispatch_queue_t disk_queue =
      dispatch_queue_create("com.google.santad.disk_queue", DISPATCH_QUEUE_SERIAL);

    _esAuthQueue =
      dispatch_queue_create("com.google.santa.daemon.es_device_auth", DISPATCH_QUEUE_CONCURRENT);

    _diskArbSession = DASessionCreate(NULL);
    DASessionSetDispatchQueue(_diskArbSession, disk_queue);

    if (@available(macos 10.15, *)) [self initES];
  }
  return self;
}

- (void)initES API_AVAILABLE(macos(10.15)) {
  while (!self.client) {
    es_client_t *client = NULL;
    es_new_client_result_t ret = es_new_client(&client, ^(es_client_t *c, const es_message_t *m) {
      // Set timeout to 5 seconds before the ES deadline.
      [self handleESMessageWithTimeout:m
                            withClient:c
                               timeout:dispatch_time(m->deadline, NSEC_PER_SEC * -5)];
    });

    switch (ret) {
      case ES_NEW_CLIENT_RESULT_SUCCESS:
        LOGI(@"Connected to EndpointSecurity");
        _client = client;
        return;
      case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
        LOGE(@"Unable to create EndpointSecurity client, not full-disk access permitted");
        LOGE(@"Sleeping for 30s before restarting.");
        sleep(30);
        exit(ret);
      default:
        LOGE(@"Unable to create es client: %d. Sleeping for a minute.", ret);
        sleep(60);
        continue;
    }
  }
}

- (void)listenES API_AVAILABLE(macos(10.15)) {
  while (!self.client)
    usleep(100000);  // 100ms

  es_event_type_t events[] = {
    ES_EVENT_TYPE_AUTH_MOUNT,
  };

  es_return_t sret = es_subscribe(self.client, events, sizeof(events) / sizeof(es_event_type_t));
  if (sret != ES_RETURN_SUCCESS)
    LOGE(@"SNTDeviceManager: unable to subscribe to auth mount events: %d", sret);
}

- (void)listenDA {
  DARegisterDiskAppearedCallback(_diskArbSession, NULL, diskAppearedCallback,
                                 (__bridge void *)self);
  DARegisterDiskDescriptionChangedCallback(_diskArbSession, NULL, NULL,
                                           diskDescriptionChangedCallback, (__bridge void *)self);
  DARegisterDiskDisappearedCallback(_diskArbSession, NULL, diskDisappearedCallback,
                                    (__bridge void *)self);
}

- (void)listen {
  [self listenDA];
  if (@available(macos 10.15, *)) [self listenES];
  self.subscribed = YES;
}

- (void)handleAuthMount:(const es_message_t *)m
             withClient:(es_client_t *)c API_AVAILABLE(macos(10.15)) {
  if (!self.blockUSBMount) {
    es_respond_auth_result(self.client, m, ES_AUTH_RESULT_ALLOW, false);
    return;
  }

  long mountMode = m->event.mount.statfs->f_flags;
  pid_t pid = audit_token_to_pid(m->process->audit_token);
  LOGI(@"SNTDeviceManager: mount syscall arriving from path: %s, pid: %d, fflags: %lu",
       m->process->executable->path.data, pid, mountMode);

  DADiskRef disk =
    DADiskCreateFromBSDName(NULL, self.diskArbSession, m->event.mount.statfs->f_mntfromname);
  CFAutorelease(disk);

  // TODO(tnek): Log all of the other attributes available in diskInfo into a structured log format.
  NSDictionary *diskInfo = CFBridgingRelease(DADiskCopyDescription(disk));
  BOOL isRemovable = [diskInfo[(__bridge NSString *)kDADiskDescriptionMediaRemovableKey] boolValue];
  BOOL isUSB = [diskInfo[@"DADeviceProtocol"] isEqualTo:@"USB"];

  if (!isRemovable || !isUSB) {
    es_respond_auth_result(self.client, m, ES_AUTH_RESULT_ALLOW, false);
    return;
  }

  es_respond_auth_result(self.client, m, ES_AUTH_RESULT_DENY, false);

  if (self.remountArgs != nil && [self.remountArgs count] > 0) {
    long remountOpts = mountArgsToMask(self.remountArgs);
    if (mountMode & remountOpts) {
      es_respond_auth_result(self.client, m, ES_AUTH_RESULT_ALLOW, false);
      return;
    }

    long newMode = mountMode | remountOpts;
    LOGI(@"SNTDeviceManager: remounting device '%s'->'%s', flags (%lu) -> (%lu)",
         m->event.mount.statfs->f_mntfromname, m->event.mount.statfs->f_mntonname, mountMode,
         newMode);
    [self remount:disk mountMode:newMode];
  }
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

// handleESMessage handles an ES message synchronously. This will block all incoming ES events
// until either we serve a response or we hit the auth deadline. Prefer [SNTDeviceManager
// handleESMessageWithTimeout]
// TODO(tnek): generalize this timeout handling logic so that EndpointSecurityManager can use it
// too.
- (void)handleESMessageWithTimeout:(const es_message_t *)m
                        withClient:(es_client_t *)c
                           timeout:(dispatch_time_t)timeout API_AVAILABLE(macos(10.15)) {
  // ES will kill our whole client if we don't meet the es_message auth deadline, so we try to
  // gracefully handle it with a deny-by-default in the worst-case before it can do that.
  // This isn't an issue for notify events, so we're in no rush for those.
  std::shared_ptr<std::atomic<bool>> responded;
  if (m->action_type == ES_ACTION_TYPE_AUTH) {
    responded = std::make_shared<std::atomic<bool>>(false);
    dispatch_after(timeout, self.esAuthQueue, ^(void) {
      if (responded->load()) return;
      LOGE(@"SNTDeviceManager: deadline reached: deny pid=%d ret=%d",
           audit_token_to_pid(m->process->audit_token),
           es_respond_auth_result(c, m, ES_AUTH_RESULT_DENY, false));
    });
  }

  // TODO(tnek): migrate to es_retain_message.
  es_message_t *mc = es_copy_message(m);
  dispatch_async(self.esAuthQueue, ^{
    [self handleESMessage:m withClient:c];

    if (m->action_type == ES_ACTION_TYPE_AUTH) {
      responded->store(true);
    }

    es_free_message(mc);
  });
}

- (void)handleESMessage:(const es_message_t *)m
             withClient:(es_client_t *)c API_AVAILABLE(macos(10.15)) {
  switch (m->event_type) {
    case ES_EVENT_TYPE_AUTH_MOUNT: [self handleAuthMount:m withClient:c];
    // Intentional fallthrough
    // TODO(tnek): log any extra data here about mounts.
    case ES_EVENT_TYPE_NOTIFY_MOUNT: {
      break;
    }
    default: LOGE(@"SNTDeviceManager: unexpected event type: %d", m->event_type);
  }
}

@end
