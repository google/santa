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
    [self reloadConfigData];
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
  if (self.configData[kMachineOwnerPlistFileKey] && self.configData[kMachineOwnerPlistKeyKey]) {
    NSDictionary *plist =
        [NSDictionary dictionaryWithContentsOfFile:self.configData[kMachineOwnerPlistFileKey]];
    return plist[self.configData[kMachineOwnerPlistKeyKey]];
  }

  if (self.configData[kMachineOwnerKey]) {
    return self.configData[kMachineOwnerKey];
  }

  return @"";
}

- (NSString *)machineID {
  NSString *machineId;

  if (self.configData[kMachineIDPlistFileKey] && self.configData[kMachineIDPlistKeyKey]) {
    NSDictionary *plist =
        [NSDictionary dictionaryWithContentsOfFile:self.configData[kMachineIDPlistFileKey]];
    machineId = plist[kMachineIDPlistKeyKey];
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
    [self reloadConfigData];
    self.configData[kClientModeKey] = @(newMode);
    [self saveConfigToDisk];
  }
}

- (BOOL)logAllEvents {
  return [self.configData[kLogAllEventsKey] boolValue];
}

- (void)setLogAllEvents:(BOOL)logAllEvents {
  [self reloadConfigData];
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
  NSFileManager *fm = [NSFileManager defaultManager];

  if (![fm fileExistsAtPath:self.configFilePath]) {
    _configData = [NSMutableDictionary dictionary];
    return;
  }

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
    fprintf(stderr, "%s\n", [[NSString stringWithFormat:@"Could not read configuration file %@: %@",
            self.configFilePath, [error localizedDescription]] UTF8String]);

    _configData = [NSMutableDictionary dictionary];
    return;
  }

  NSDictionary *configData =
      [NSPropertyListSerialization propertyListWithData:readData
                                                options:kCFPropertyListImmutable
                                                 format:NULL
                                                  error:&error];
  if (error) {
    fprintf(stderr, "%s\n",
        [[NSString stringWithFormat:@"Could not parse configuration file %@: %@",
            self.configFilePath,
            [error localizedDescription]] UTF8String]);

    _configData = [NSMutableDictionary dictionary];
    return;
  }

  _configData = [configData mutableCopy];
}

@end
