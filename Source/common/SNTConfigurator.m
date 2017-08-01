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

/// Creating NSRegularExpression objects is not fast, so cache them.
@property NSRegularExpression *cachedFileChangesRegex;
@property NSRegularExpression *cachedWhitelistDirRegex;
@property NSRegularExpression *cachedBlacklistDirRegex;

/// Array of keys that cannot be changed while santad is running if santad didn't make the change.
@property(readonly) NSArray *protectedKeys;
@end

@implementation SNTConfigurator

/// The hard-coded path to the config file
NSString *const kDefaultConfigFilePath = @"/var/db/santa/config.plist";

/// The keys in the config file
static NSString *const kClientModeKey = @"ClientMode";
static NSString *const kFileChangesRegexKey = @"FileChangesRegex";
static NSString *const kWhitelistRegexKey = @"WhitelistRegex";
static NSString *const kBlacklistRegexKey = @"BlacklistRegex";
static NSString *const kEnablePageZeroProtectionKey = @"EnablePageZeroProtection";

static NSString *const kMoreInfoURLKey = @"MoreInfoURL";
static NSString *const kEventDetailURLKey = @"EventDetailURL";
static NSString *const kEventDetailTextKey = @"EventDetailText";
static NSString *const kUnknownBlockMessage = @"UnknownBlockMessage";
static NSString *const kBannedBlockMessage = @"BannedBlockMessage";
static NSString *const kModeNotificationMonitor = @"ModeNotificationMonitor";
static NSString *const kModeNotificationLockdown = @"ModeNotificationLockdown";

static NSString *const kSyncBaseURLKey = @"SyncBaseURL";
static NSString *const kFullSyncLastSuccess = @"FullSyncLastSuccess";
static NSString *const kRuleSyncLastSuccess = @"RuleSyncLastSuccess";
static NSString *const kSyncCleanRequired = @"SyncCleanRequired";
static NSString *const kClientAuthCertificateFileKey = @"ClientAuthCertificateFile";
static NSString *const kClientAuthCertificatePasswordKey = @"ClientAuthCertificatePassword";
static NSString *const kClientAuthCertificateCNKey = @"ClientAuthCertificateCN";
static NSString *const kClientAuthCertificateIssuerKey = @"ClientAuthCertificateIssuerCN";
static NSString *const kServerAuthRootsDataKey = @"ServerAuthRootsData";
static NSString *const kServerAuthRootsFileKey = @"ServerAuthRootsFile";

static NSString *const kMachineOwnerKey = @"MachineOwner";
static NSString *const kMachineIDKey = @"MachineID";

static NSString *const kMachineOwnerPlistFileKey = @"MachineOwnerPlist";
static NSString *const kMachineOwnerPlistKeyKey = @"MachineOwnerKey";

static NSString *const kMachineIDPlistFileKey = @"MachineIDPlist";
static NSString *const kMachineIDPlistKeyKey = @"MachineIDKey";

- (instancetype)initWithFilePath:(NSString *)filePath {
  self = [super init];
  if (self) {
    _configFilePath = filePath;
    [self reloadConfigData];
  }
  return self;
}

#pragma mark Singleton retriever

+ (instancetype)configurator {
  static SNTConfigurator *sharedConfigurator = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedConfigurator = [[SNTConfigurator alloc] initWithFilePath:kDefaultConfigFilePath];
  });
  return sharedConfigurator;
}

#pragma mark Protected Keys

- (NSArray *)protectedKeys {
  return @[ kClientModeKey, kWhitelistRegexKey, kBlacklistRegexKey,
            kFileChangesRegexKey, kSyncBaseURLKey ];
}

#pragma mark Public Interface

- (SNTClientMode)clientMode {
  NSInteger cm = SNTClientModeUnknown;

  id mode = self.configData[kClientModeKey];
  if ([mode respondsToSelector:@selector(longLongValue)]) {
    cm = (NSInteger)[mode longLongValue];
  }

  if (cm == SNTClientModeMonitor || cm == SNTClientModeLockdown) {
    return (SNTClientMode)cm;
  } else {
    LOGE(@"Client mode was set to bad value: %ld. Resetting to MONITOR.", cm);
    self.clientMode = SNTClientModeMonitor;
    return SNTClientModeMonitor;
  }
}

- (void)setClientMode:(SNTClientMode)newMode {
  if (newMode == SNTClientModeMonitor || newMode == SNTClientModeLockdown) {
    self.configData[kClientModeKey] = @(newMode);
    [self saveConfigToDisk];
  } else {
    LOGW(@"Ignoring request to change client mode to %ld", newMode);
  }
}

- (NSRegularExpression *)whitelistPathRegex {
  if (!self.cachedWhitelistDirRegex && self.configData[kWhitelistRegexKey]) {
    NSString *re = self.configData[kWhitelistRegexKey];
    if (![re hasPrefix:@"^"]) re = [@"^" stringByAppendingString:re];
    self.cachedWhitelistDirRegex = [NSRegularExpression regularExpressionWithPattern:re
                                                                             options:0
                                                                               error:NULL];
  }
  return self.cachedWhitelistDirRegex;
}

- (void)setWhitelistPathRegex:(NSRegularExpression *)re {
  if (!re) {
    [self.configData removeObjectForKey:kWhitelistRegexKey];
  } else {
    self.configData[kWhitelistRegexKey] = [re pattern];
  }
  self.cachedWhitelistDirRegex = nil;
  [self saveConfigToDisk];
}

- (NSRegularExpression *)blacklistPathRegex {
  if (!self.cachedBlacklistDirRegex && self.configData[kBlacklistRegexKey]) {
    NSString *re = self.configData[kBlacklistRegexKey];
    if (![re hasPrefix:@"^"]) re = [@"^" stringByAppendingString:re];
    self.cachedBlacklistDirRegex = [NSRegularExpression regularExpressionWithPattern:re
                                                                             options:0
                                                                               error:NULL];
  }
  return self.cachedBlacklistDirRegex;
}

- (void)setBlacklistPathRegex:(NSRegularExpression *)re {
  if (!re) {
    [self.configData removeObjectForKey:kBlacklistRegexKey];
  } else {
    self.configData[kBlacklistRegexKey] = [re pattern];
  }
  self.cachedBlacklistDirRegex = nil;
  [self saveConfigToDisk];
}

- (NSRegularExpression *)fileChangesRegex {
  if (!self.cachedFileChangesRegex && self.configData[kFileChangesRegexKey]) {
    NSString *re = self.configData[kFileChangesRegexKey];
    if (![re hasPrefix:@"^"]) re = [@"^" stringByAppendingString:re];
    self.cachedFileChangesRegex = [NSRegularExpression regularExpressionWithPattern:re
                                                                            options:0
                                                                              error:NULL];
  }
  return self.cachedFileChangesRegex;
}

- (void)setFileChangesRegex:(NSRegularExpression *)re {
  if (!re) {
    [self.configData removeObjectForKey:kFileChangesRegexKey];
  } else {
    self.configData[kFileChangesRegexKey] = [re pattern];
  }
  self.cachedFileChangesRegex = nil;
  [self saveConfigToDisk];
}

- (BOOL)enablePageZeroProtection {
  NSNumber *keyValue = self.configData[kEnablePageZeroProtectionKey];
  return keyValue ? [keyValue boolValue] : YES;
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

- (NSString *)unknownBlockMessage {
  return self.configData[kUnknownBlockMessage];
}

- (NSString *)bannedBlockMessage {
  return self.configData[kBannedBlockMessage];
}

- (NSString *)modeNotificationMonitor {
  return self.configData[kModeNotificationMonitor];
}

- (NSString *)modeNotificationLockdown {
  return self.configData[kModeNotificationLockdown];
}

- (NSURL *)syncBaseURL {
  NSString *urlStr = self.configData[kSyncBaseURLKey];
  if (urlStr) {
    NSURL *url = [NSURL URLWithString:urlStr];
    if (!url) LOGW(@"SyncBaseURL is not a valid URL!");
    return url;
  }
  return nil;
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

- (NSDate *)fullSyncLastSuccess {
  return self.configData[kFullSyncLastSuccess];
}

- (void)setFullSyncLastSuccess:(NSDate *)fullSyncLastSuccess {
  self.configData[kFullSyncLastSuccess] = fullSyncLastSuccess;
  [self saveConfigToDisk];
  self.ruleSyncLastSuccess = fullSyncLastSuccess;
}

- (NSDate *)ruleSyncLastSuccess {
  return self.configData[kRuleSyncLastSuccess];
}

- (void)setRuleSyncLastSuccess:(NSDate *)ruleSyncLastSuccess {
  self.configData[kRuleSyncLastSuccess] = ruleSyncLastSuccess;
  [self saveConfigToDisk];
}

- (BOOL)syncCleanRequired {
  return [self.configData[kSyncCleanRequired] boolValue];
}

- (void)setSyncCleanRequired:(BOOL)syncCleanRequired {
  self.configData[kSyncCleanRequired] = @(syncCleanRequired);
  [self saveConfigToDisk];
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

  if ([machineId length] == 0) {
    machineId = [SNTSystemInfo hardwareUUID];
  }

  return machineId;
}

- (void)reloadConfigData {
  NSFileManager *fm = [NSFileManager defaultManager];
  if (![fm fileExistsAtPath:self.configFilePath]) {
    // As soon as saveConfigToDisk is called, reloadConfigData will be called again because
    // of the SNTFileWatchers on the config path. No need to use dictionaryWithCapacity: here.
    self.configData = [NSMutableDictionary dictionary];
    self.configData[kClientModeKey] = @(SNTClientModeMonitor);
    [self saveConfigToDisk];
    return;
  };

  NSError *error;
  NSData *readData = [NSData dataWithContentsOfFile:self.configFilePath
                                            options:NSDataReadingMappedIfSafe
                                              error:&error];
  if (error) {
    LOGE(@"Could not read configuration file: %@, replacing.", [error localizedDescription]);
    [self saveConfigToDisk];
    return;
  }

  NSMutableDictionary *configData =
      [NSPropertyListSerialization propertyListWithData:readData
                                                options:NSPropertyListMutableContainers
                                                 format:NULL
                                                  error:&error];
  if (error) {
    LOGE(@"Could not parse configuration file: %@, replacing.", [error localizedDescription]);
    [self saveConfigToDisk];
    return;
  }

  if (self.syncBaseURL) {
    // Ensure no-one is trying to change protected keys behind our back.
    BOOL changed = NO;
    if (geteuid() == 0) {
      for (NSString *key in self.protectedKeys) {
        if (((self.configData[key] && !configData[key]) ||
             (!self.configData[key] && configData[key]) ||
             (self.configData[key] && ![self.configData[key] isEqual:configData[key]]))) {
          if (self.configData[key]) {
            configData[key] = self.configData[key];
          } else {
            [configData removeObjectForKey:key];
          }
          changed = YES;
          LOGI(@"Ignoring changed configuration key: %@", key);
        }
      }
    }
    self.configData = configData;
    if (changed) [self saveConfigToDisk];
  } else {
    self.configData = configData;
  }
}

#pragma mark Private

///
///  Saves the current @c self.configData to disk.
///
- (void)saveConfigToDisk {
  if (geteuid() != 0) return;
  [self.configData writeToFile:self.configFilePath atomically:YES];
}

@end
