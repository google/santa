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

#import "SNTConfigurator.h"

#import "SNTLogging.h"
#import "SNTSystemInfo.h"

@interface SNTConfigurator ()
@property NSString *configFilePath;
@property NSMutableDictionary *configData;

@property dispatch_source_t fileMonitoringSource;
@property(strong) void (^fileEventHandler)(void);
@property(strong) void (^fileCancelHandler)(void);

@end

@implementation SNTConfigurator

/// The hard-coded path to the config file
static NSString * const kConfigFilePath = @"/var/db/santa/config.plist";

/// The keys in the config file
static NSString * const kClientModeKey = @"ClientMode";

static NSString * const kLogAllEventsKey = @"LogAllEvents";

static NSString * const kMoreInfoURLKey = @"MoreInfoURL";
static NSString * const kEventDetailURLKey = @"EventDetailURL";
static NSString * const kEventDetailTextKey = @"EventDetailText";

static NSString * const kSyncBaseURLKey = @"SyncBaseURL";
static NSString * const kClientAuthCertificateFileKey = @"ClientAuthCertificateFile";
static NSString * const kClientAuthCertificatePasswordKey = @"ClientAuthCertificatePassword";
static NSString * const kClientAuthCertificateCNKey = @"ClientAuthCertificateCN";
static NSString * const kClientAuthCertificateIssuerKey = @"ClientAuthCertificateIssuerCN";
static NSString * const kServerAuthRootsDataKey = @"ServerAuthRootsData";
static NSString * const kServerAuthRootsFileKey = @"ServerAuthRootsFile";

static NSString * const kMachineOwnerKey = @"MachineOwner";
static NSString * const kMachineIDKey = @"MachineID";

static NSString * const kMachineOwnerPlistFileKey = @"MachineOwnerPlist";
static NSString * const kMachineOwnerPlistKeyKey = @"MachineOwnerKey";

static NSString * const kMachineIDPlistFileKey = @"MachineIDPlist";
static NSString * const kMachineIDPlistKeyKey = @"MachineIDKey";

- (instancetype)initWithFilePath:(NSString *)filePath {
  self = [super init];
  if (self) {
    _configFilePath = filePath;
    [self beginWatchingConfigFile];
  }
  return self;
}

# pragma mark Singleton retriever

+ (instancetype)configurator {
  static SNTConfigurator *sharedConfigurator = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedConfigurator = [[SNTConfigurator alloc] initWithFilePath:kConfigFilePath];
  });
  return sharedConfigurator;
}

# pragma mark Public Interface

- (NSURL *)syncBaseURL {
  return [NSURL URLWithString:self.configData[kSyncBaseURLKey]];
}

- (NSString *)syncClientAuthCertificateFile {
  return self.configData[kClientAuthCertificateFileKey];
}

- (NSString *)syncClientAuthCertificatePassword {
  return self.configData[kClientAuthCertificatePasswordKey];
}

- (NSString *)syncClientAuthCertificateCn {
  return self.configData[kClientAuthCertificateCNKey];
}

- (NSString *)syncClientAuthCertificateIssuer {
  return self.configData[kClientAuthCertificateIssuerKey];
}

- (NSData *)syncServerAuthRootsData {
  return self.configData[kServerAuthRootsDataKey];
}

- (NSString *)syncServerAuthRootsFile {
  return self.configData[kServerAuthRootsFileKey];
}

- (NSString *)machineOwner {
  NSString *machineOwner;

  if (self.configData[kMachineOwnerPlistFileKey] && self.configData[kMachineOwnerPlistKeyKey]) {
    NSDictionary *plist =
        [NSDictionary dictionaryWithContentsOfFile:self.configData[kMachineOwnerPlistFileKey]];
    machineOwner = plist[self.configData[kMachineOwnerPlistKeyKey]];
  }

  if (self.configData[kMachineOwnerKey]) {
    machineOwner = self.configData[kMachineOwnerKey];
  }

  if (!machineOwner) machineOwner = @"";

  return machineOwner;
}

- (NSString *)machineID {
  NSString *machineId;

  if (self.configData[kMachineIDPlistFileKey] && self.configData[kMachineIDPlistKeyKey]) {
    NSDictionary *plist =
        [NSDictionary dictionaryWithContentsOfFile:self.configData[kMachineIDPlistFileKey]];
    machineId = plist[self.configData[kMachineIDPlistKeyKey]];
  }

  if (self.configData[kMachineIDKey]) {
    machineId = self.configData[kMachineIDKey];
  }

  if (!machineId || [machineId isEqual:@""]) {
    machineId = [SNTSystemInfo hardwareUUID];
  }

  return machineId;
}

- (santa_clientmode_t)clientMode {
  int cm = [self.configData[kClientModeKey] intValue];
  if (cm > CLIENTMODE_UNKNOWN && cm < CLIENTMODE_MAX) {
    return cm;
  } else {
    self.configData[kClientModeKey] = @(CLIENTMODE_MONITOR);
    return CLIENTMODE_MONITOR;
  }
}

- (void)setClientMode:(santa_clientmode_t)newMode {
  if (newMode > CLIENTMODE_UNKNOWN && newMode < CLIENTMODE_MAX) {
    self.configData[kClientModeKey] = @(newMode);
    [self saveConfigToDisk];
  }
}

- (BOOL)logAllEvents {
  return [self.configData[kLogAllEventsKey] boolValue];
}

- (void)setLogAllEvents:(BOOL)logAllEvents {
  self.configData[kLogAllEventsKey] = @(logAllEvents);
  [self saveConfigToDisk];
}

- (NSURL *)moreInfoURL {
  return [NSURL URLWithString:self.configData[kMoreInfoURLKey]];
}

- (NSString *)eventDetailURL {
  return self.configData[kEventDetailURLKey];
}

- (NSString *)eventDetailText {
  return self.configData[kEventDetailTextKey];
}

#pragma mark Private

///
///  Saves the current @c _configData to disk.
///
- (void)saveConfigToDisk {
  [self.configData writeToFile:kConfigFilePath atomically:YES];
}

///
///  Populate @c self.configData, using the config file on disk if possible,
///  otherwise an empty mutable dictionary.
///
///  If the config file's permissions are not @c 0644, will attempt to set them
///  but will fail silently if this cannot be done.
///
- (void)reloadConfigData {
  if (!self.configData) self.configData = [NSMutableDictionary dictionary];

  NSFileManager *fm = [NSFileManager defaultManager];
  if (![fm fileExistsAtPath:self.configFilePath]) return;

  // Ensure the config file permissions are 0644. Fail silently if they can't be changed.
  NSDictionary *fileAttrs = [fm attributesOfItemAtPath:self.configFilePath error:nil];
  if ([fileAttrs filePosixPermissions] != 0644) {
    [fm setAttributes:@{ NSFilePosixPermissions: @(0644) }
         ofItemAtPath:self.configFilePath
                error:nil];
  }

  NSError *error;
  NSData *readData = [NSData dataWithContentsOfFile:self.configFilePath
                                            options:NSDataReadingMappedIfSafe
                                              error:&error];
  if (error) {
    LOGE(@"Could not read configuration file: %@", [error localizedDescription]);
    return;
  }

  NSDictionary *configData =
      [NSPropertyListSerialization propertyListWithData:readData
                                                options:kCFPropertyListImmutable
                                                 format:NULL
                                                  error:&error];
  if (error) {
    LOGE(@"Could not parse configuration file: %@", [error localizedDescription]);
    return;
  }

  // Ensure user isn't trying to change the client mode while running, only santactl can do that.
  if (self.configData[kClientModeKey] && configData[kClientModeKey] &&
      ![self.configData[kClientModeKey] isEqual:configData[kClientModeKey]] &&
      [[[NSProcessInfo processInfo] processName] isEqual:@"santad"]) {
    LOGW(@"Client mode in config file was changed behind our back, resetting.");
    NSMutableDictionary *configDataMutable = [configData mutableCopy];
    configDataMutable[kClientModeKey] = self.configData[kClientModeKey];
    self.configData = configDataMutable;
    [self saveConfigToDisk];
  } else {
    self.configData = [configData mutableCopy];
  }
}

- (void)beginWatchingConfigFile {
  if (self.fileMonitoringSource) return;

  dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0);
  if (!queue) return;

  __weak typeof(self) weakSelf = self;
  int mask = (DISPATCH_VNODE_DELETE | DISPATCH_VNODE_WRITE |
              DISPATCH_VNODE_EXTEND | DISPATCH_VNODE_RENAME);

  self.fileEventHandler = ^{
    unsigned long l = dispatch_source_get_data(weakSelf.fileMonitoringSource);
    if (l & DISPATCH_VNODE_DELETE || l & DISPATCH_VNODE_RENAME) {
      dispatch_source_cancel(weakSelf.fileMonitoringSource);
    } else {
      [weakSelf reloadConfigData];
    }
  };

  self.fileCancelHandler = ^{
    int fd;
    if (weakSelf.fileMonitoringSource) {
      fd = (int)dispatch_source_get_handle(weakSelf.fileMonitoringSource);
      close(fd);
    }

    while ((fd = open([weakSelf.configFilePath fileSystemRepresentation], O_EVTONLY)) < 0) {
      sleep(1);
    }

    weakSelf.fileMonitoringSource = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_VNODE, fd, mask, queue);
    dispatch_source_set_event_handler(weakSelf.fileMonitoringSource, weakSelf.fileEventHandler);
    dispatch_source_set_cancel_handler(weakSelf.fileMonitoringSource, weakSelf.fileCancelHandler);
    dispatch_resume(weakSelf.fileMonitoringSource);
    [weakSelf reloadConfigData];
  };

  dispatch_async(queue, self.fileCancelHandler);
}

@end
