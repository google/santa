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

#include <sys/stat.h>

#import "SNTLogging.h"
#import "SNTSystemInfo.h"

@interface SNTConfigurator ()
@property NSMutableDictionary *configData;

/// Creating NSRegularExpression objects is not fast, so cache them.
@property NSRegularExpression *cachedFileChangesRegex;
@property NSRegularExpression *cachedWhitelistDirRegex;
@property NSRegularExpression *cachedBlacklistDirRegex;

/// A NSUserDefaults object set to use the com.google.santa suite.
@property(readonly, nonatomic) NSUserDefaults *defaults;

/// Keys used by a mobileconfig or sync server
@property(readonly, nonatomic) NSArray *syncServerKeys;
@property(readonly, nonatomic) NSArray *mobileConfigKeys;
@end

@implementation SNTConfigurator

/// The hard-coded path to the sync state file.
NSString *const kSyncStateFilePath = @"/var/db/santa/sync-state.plist";

/// The domain used by mobileconfig.
static NSString *const kMobileConfigDomain = @"com.google.santa";

/// The hard-coded path to the mobileconfig file.
NSString *const kMobileConfigFilePath = @"/Library/Managed Preferences/com.google.santa.plist";

/// The keys managed by a mobileconfig.
static NSString *const kSyncBaseURLKey = @"SyncBaseURL";
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

static NSString *const kMoreInfoURLKey = @"MoreInfoURL";
static NSString *const kEventDetailURLKey = @"EventDetailURL";
static NSString *const kEventDetailTextKey = @"EventDetailText";
static NSString *const kUnknownBlockMessage = @"UnknownBlockMessage";
static NSString *const kBannedBlockMessage = @"BannedBlockMessage";
static NSString *const kModeNotificationMonitor = @"ModeNotificationMonitor";
static NSString *const kModeNotificationLockdown = @"ModeNotificationLockdown";

static NSString *const kEnablePageZeroProtectionKey = @"EnablePageZeroProtection";

// The keys managed by a sync server or mobileconfig.
static NSString *const kClientModeKey = @"ClientMode";
static NSString *const kWhitelistRegexKey = @"WhitelistRegex";
static NSString *const kBlacklistRegexKey = @"BlacklistRegex";
static NSString *const kFileChangesRegexKey = @"FileChangesRegex";

// The keys managed by a sync server.
static NSString *const kFullSyncLastSuccess = @"FullSyncLastSuccess";
static NSString *const kRuleSyncLastSuccess = @"RuleSyncLastSuccess";
static NSString *const kSyncCleanRequired = @"SyncCleanRequired";

- (instancetype)init {
  self = [super init];
  if (self) {
    _defaults = [[NSUserDefaults alloc] initWithSuiteName:kMobileConfigDomain];
    _syncServerKeys = @[
        kClientModeKey, kWhitelistRegexKey, kBlacklistRegexKey, kFileChangesRegexKey,
        kFullSyncLastSuccess, kRuleSyncLastSuccess, kSyncCleanRequired
    ];
    _mobileConfigKeys = @[
        kClientModeKey, kFileChangesRegexKey, kWhitelistRegexKey, kBlacklistRegexKey,
        kEnablePageZeroProtectionKey, kMoreInfoURLKey, kEventDetailURLKey, kEventDetailTextKey,
        kUnknownBlockMessage, kBannedBlockMessage, kModeNotificationMonitor,
        kModeNotificationLockdown, kSyncBaseURLKey, kClientAuthCertificateFileKey,
        kClientAuthCertificatePasswordKey, kClientAuthCertificateCNKey,
        kClientAuthCertificateIssuerKey, kServerAuthRootsDataKey, kServerAuthRootsFileKey,
        kMachineOwnerKey, kMachineIDKey, kMachineOwnerPlistFileKey, kMachineOwnerPlistKeyKey,
        kMachineIDPlistFileKey, kMachineIDPlistKeyKey
    ];
    [self reloadConfigData];
  }
  return self;
}

#pragma mark Singleton retriever

+ (instancetype)configurator {
  static SNTConfigurator *sharedConfigurator;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedConfigurator = [[SNTConfigurator alloc] init];
  });
  return sharedConfigurator;
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
    [self saveSyncStateToDisk];
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
  [self saveSyncStateToDisk];
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
  [self saveSyncStateToDisk];
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
  [self saveSyncStateToDisk];
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
  [self saveSyncStateToDisk];
  self.ruleSyncLastSuccess = fullSyncLastSuccess;
}

- (NSDate *)ruleSyncLastSuccess {
  return self.configData[kRuleSyncLastSuccess];
}

- (void)setRuleSyncLastSuccess:(NSDate *)ruleSyncLastSuccess {
  self.configData[kRuleSyncLastSuccess] = ruleSyncLastSuccess;
  [self saveSyncStateToDisk];
}

- (BOOL)syncCleanRequired {
  return [self.configData[kSyncCleanRequired] boolValue];
}

- (void)setSyncCleanRequired:(BOOL)syncCleanRequired {
  self.configData[kSyncCleanRequired] = @(syncCleanRequired);
  [self saveSyncStateToDisk];
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
  // Load the mobileconfig
  self.configData = [self mobileConfig];
  if (!self.configData[kClientModeKey]) {
    // Default to Monitor if the config is missing or invalid
    self.configData[kClientModeKey] = @(SNTClientModeMonitor);
  }

  // Nothing else to do if a sync server is not involved
  if (!self.configData[kSyncBaseURLKey]) return;

  // Load the last known sync state
  if (![[NSFileManager defaultManager] fileExistsAtPath:kSyncStateFilePath]) return;
  NSMutableDictionary *syncState = [self syncState];
  if (!self) return;

  // Overwrite or add the sync state to the running config
  for (NSString *key in [self syncServerKeys]) {
    self.configData[key] = syncState[key];
  }
  [self saveSyncStateToDisk];
}

#pragma mark Private

- (NSMutableDictionary *)syncState {
  NSError *error;
  NSData *readData = [NSData dataWithContentsOfFile:kSyncStateFilePath
                                            options:NSDataReadingMappedIfSafe
                                              error:&error];
  if (!readData) {
    LOGE(@"Could not read sync state file: %@, replacing.", [error localizedDescription]);
    [self saveSyncStateToDisk];
    return nil;
  }

  NSMutableDictionary *syncState =
      [NSPropertyListSerialization propertyListWithData:readData
                                                options:NSPropertyListMutableContainers
                                                 format:NULL
                                                  error:&error];
  if (!syncState) {
    LOGE(@"Could not parse sync state file: %@, replacing.", [error localizedDescription]);
    [self saveSyncStateToDisk];
    return nil;
  }

  return syncState;
}

///
///  Saves the current effective syncState to disk.
///
- (void)saveSyncStateToDisk {
  // Only santad should write to this file.
  if (geteuid() != 0) return;
  NSMutableDictionary *syncState =
      [NSMutableDictionary dictionaryWithCapacity:[self syncServerKeys].count];
  for (NSString *key in [self syncServerKeys]) {
    syncState[key] = self.configData[key];
  }
  [syncState writeToFile:kSyncStateFilePath atomically:YES];
  [[NSFileManager defaultManager] setAttributes:@{ NSFilePosixPermissions : @0644 }
                                   ofItemAtPath:kSyncStateFilePath error:NULL];
}

///
///  Ensure permissions are 0644.
///  Revert any out-of-band changes.
///
- (void)syncStateFileChanged:(unsigned long)data {
  if (data & DISPATCH_VNODE_ATTRIB) {
    const char *cPath = [kSyncStateFilePath fileSystemRepresentation];
    struct stat fileStat;
    stat(cPath, &fileStat);
    int mask = S_IRWXU | S_IRWXG | S_IRWXO;
    int desired = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (fileStat.st_uid != 0 || fileStat.st_gid != 0 || (fileStat.st_mode & mask) != desired) {
      LOGD(@"Sync state file permissions changed, fixing.");
      chown(cPath, 0, 0);
      chmod(cPath, desired);
    }
  } else {
    NSDictionary *syncState = [self syncState];
    for (NSString *key in self.syncServerKeys) {
      if (((self.configData[key] && !syncState[key]) ||
           (!self.configData[key] && syncState[key]) ||
           (self.configData[key] && ![self.configData[key] isEqualTo:syncState[key]]))) {
        // Ignore sync url and dates
        if ([key isEqualToString:kSyncBaseURLKey] ||
            [key isEqualToString:kRuleSyncLastSuccess] ||
            [key isEqualToString:kFullSyncLastSuccess]) continue;
        LOGE(@"Sync state file changed, replacing");
        [self saveSyncStateToDisk];
        return;
      }
    }
  }
}

///
///  Returns a config provided by a com.google.santa mobileconfig or an empty
///  NSMutableDictionary object if no config applies.
///
- (NSMutableDictionary *)mobileConfig {
  NSMutableDictionary *config =
      [NSMutableDictionary dictionaryWithCapacity:[self mobileConfigKeys].count];
  for (NSString *key in [self mobileConfigKeys]) {
    if ([self.defaults objectIsForcedForKey:key]) {
      config[key] = [self.defaults objectForKey:key];
    }
  }
  if (config[kSyncBaseURLKey]) {
    for (NSString *key in [self syncServerKeys]) {
      if ([key isEqualToString:kSyncBaseURLKey]) continue;
      [config removeObjectForKey:key];
    }
  }
  return config;
}

@end
