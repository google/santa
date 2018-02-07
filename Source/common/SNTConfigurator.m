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

#import "SNTFileWatcher.h"
#import "SNTLogging.h"
#import "SNTStrengthify.h"
#import "SNTSystemInfo.h"

@interface SNTConfigurator ()
/// A NSUserDefaults object set to use the com.google.santa suite.
@property(readonly, nonatomic) NSUserDefaults *defaults;

// Keys and expected value types.
@property(readonly, nonatomic) NSDictionary *syncServerKeyTypes;
@property(readonly, nonatomic) NSDictionary *forcedConfigKeyTypes;

/// Holds the configurations from a sync server and mobileconfig.
@property NSMutableDictionary *syncState;
@property NSMutableDictionary *configState;

/// Watcher for the sync-state.plist.
@property(nonatomic) SNTFileWatcher *syncStateWatcher;
@end

@implementation SNTConfigurator

/// The hard-coded path to the sync state file.
NSString *const kSyncStateFilePath = @"/var/db/santa/sync-state.plist";

/// The domain used by mobileconfig.
static NSString *const kMobileConfigDomain = @"com.google.santa";

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

static NSString *const kFileChangesRegexKey = @"FileChangesRegex";

// The keys managed by a sync server or mobileconfig.
static NSString *const kClientModeKey = @"ClientMode";
static NSString *const kWhitelistRegexKey = @"WhitelistRegex";
static NSString *const kBlacklistRegexKey = @"BlacklistRegex";

// The keys managed by a sync server.
static NSString *const kFullSyncLastSuccess = @"FullSyncLastSuccess";
static NSString *const kRuleSyncLastSuccess = @"RuleSyncLastSuccess";
static NSString *const kSyncCleanRequired = @"SyncCleanRequired";

- (instancetype)init {
  self = [super init];
  if (self) {
    _syncServerKeyTypes = @{
      kClientModeKey : [NSNumber class],
      kWhitelistRegexKey : [NSRegularExpression class],
      kBlacklistRegexKey : [NSRegularExpression class],
      kFullSyncLastSuccess : [NSDate class],
      kRuleSyncLastSuccess : [NSDate class],
      kSyncCleanRequired : [NSNumber class]
    };
    _forcedConfigKeyTypes = @{
      kClientModeKey : [NSNumber class],
      kFileChangesRegexKey : [NSRegularExpression class],
      kWhitelistRegexKey : [NSRegularExpression class],
      kBlacklistRegexKey : [NSRegularExpression class],
      kEnablePageZeroProtectionKey : [NSNumber class],
      kMoreInfoURLKey : [NSString class],
      kEventDetailURLKey : [NSString class],
      kEventDetailTextKey : [NSString class],
      kUnknownBlockMessage : [NSString class],
      kBannedBlockMessage : [NSString class],
      kModeNotificationMonitor : [NSString class],
      kModeNotificationLockdown : [NSString class],
      kSyncBaseURLKey : [NSString class],
      kClientAuthCertificateFileKey : [NSString class],
      kClientAuthCertificatePasswordKey : [NSString class],
      kClientAuthCertificateCNKey : [NSString class],
      kClientAuthCertificateIssuerKey : [NSString class],
      kServerAuthRootsDataKey  : [NSData class],
      kServerAuthRootsFileKey : [NSString class],
      kMachineOwnerKey : [NSString class],
      kMachineIDKey : [NSString class],
      kMachineOwnerPlistFileKey : [NSString class],
      kMachineOwnerPlistKeyKey : [NSString class],
      kMachineIDPlistFileKey : [NSString class],
      kMachineIDPlistKeyKey : [NSString class],
    };
    _defaults = [NSUserDefaults standardUserDefaults];
    [_defaults addSuiteNamed:@"com.google.santa"];
    _configState = [self readForcedConfig];
    _syncState = [self readSyncStateFromDisk] ?: [NSMutableDictionary dictionary];
    [self startWatchingDefaults];
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

#pragma mark KVO Dependencies

+ (NSSet *)keyPathsForValuesAffectingClientMode {
  return [NSSet setWithObjects:@"syncState", @"configState", nil];
}

+ (NSSet *)keyPathsForValuesAffectingWhitelistPathRegex {
  return [NSSet setWithObjects:@"syncState", @"configState", nil];
}

+ (NSSet *)keyPathsForValuesAffectingBlacklistPathRegex {
  return [NSSet setWithObjects:@"syncState", @"configState", nil];
}

+ (NSSet *)keyPathsForValuesAffectingFileChangesRegex {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingSyncBaseURL {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingEnablePageZeroProtection {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingMoreInfoURL {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingEventDetailURL {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingEventDetailText {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingUnknownBlockMessage {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingBannedBlockMessage {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingModeNotificationMonitor {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingModeNotificationLockdown {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingSyncClientAuthCertificateFile {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingSyncClientAuthCertificatePassword {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingSyncClientAuthCertificateCn {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingSyncClientAuthCertificateIssuer {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingSyncServerAuthRootsData {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingSyncServerAuthRootsFile {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingFullSyncLastSuccess {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingMachineOwner {
  return [NSSet setWithObject:@"configState"];
}

+ (NSSet *)keyPathsForValuesAffectingMachineID {
  return [NSSet setWithObject:@"configState"];
}

#pragma mark Public Interface

- (SNTClientMode)clientMode {
  SNTClientMode cm = [self.syncState[kClientModeKey] longLongValue];
  if (cm == SNTClientModeMonitor || cm == SNTClientModeLockdown) {
    return cm;
  }

  cm = [self.configState[kClientModeKey] longLongValue];
  if (cm == SNTClientModeMonitor || cm == SNTClientModeLockdown) {
    return cm;
  }

  return SNTClientModeMonitor;
}

- (void)setSyncServerClientMode:(SNTClientMode)newMode {
  if (newMode == SNTClientModeMonitor || newMode == SNTClientModeLockdown) {
    [self updateSyncStateForKey:kClientModeKey value:@(newMode)];
  } else {
    LOGW(@"Ignoring request to change client mode to %ld", newMode);
  }
}

- (NSRegularExpression *)whitelistPathRegex {
  return self.syncState[kWhitelistRegexKey] ?: self.configState[kWhitelistRegexKey];
}

- (void)setSyncServerWhitelistPathRegex:(NSRegularExpression *)re {
  [self updateSyncStateForKey:kWhitelistRegexKey value:re];
}

- (NSRegularExpression *)blacklistPathRegex {
  return self.syncState[kBlacklistRegexKey] ?: self.configState[kBlacklistRegexKey];
}

- (void)setSyncServerBlacklistPathRegex:(NSRegularExpression *)re {
  [self updateSyncStateForKey:kBlacklistRegexKey value:re];
}

- (NSRegularExpression *)fileChangesRegex {
  return self.configState[kFileChangesRegexKey];
}

- (NSURL *)syncBaseURL {
  NSString *urlString = self.configState[kSyncBaseURLKey];
  NSURL *url = [NSURL URLWithString:urlString];
  if (urlString && !url) LOGW(@"SyncBaseURL is not a valid URL!");
  return url;
}

- (BOOL)enablePageZeroProtection {
  NSNumber *number = self.configState[kEnablePageZeroProtectionKey];
  return number ? [number boolValue] : YES;
}

- (NSURL *)moreInfoURL {
  return [NSURL URLWithString:self.configState[kMoreInfoURLKey]];
}

- (NSString *)eventDetailURL {
  return self.configState[kEventDetailURLKey];
}

- (NSString *)eventDetailText {
  return self.configState[kEventDetailTextKey];
}

- (NSString *)unknownBlockMessage {
  return self.configState[kUnknownBlockMessage];
}

- (NSString *)bannedBlockMessage {
  return self.configState[kBannedBlockMessage];
}

- (NSString *)modeNotificationMonitor {
  return self.configState[kModeNotificationMonitor];
}

- (NSString *)modeNotificationLockdown {
  return self.configState[kModeNotificationLockdown];
}

- (NSString *)syncClientAuthCertificateFile {
  return self.configState[kClientAuthCertificateFileKey];
}

- (NSString *)syncClientAuthCertificatePassword {
  return self.configState[kClientAuthCertificatePasswordKey];
}

- (NSString *)syncClientAuthCertificateCn {
  return self.configState[kClientAuthCertificateCNKey];
}

- (NSString *)syncClientAuthCertificateIssuer {
  return self.configState[kClientAuthCertificateIssuerKey];
}

- (NSData *)syncServerAuthRootsData {
  return self.configState[kServerAuthRootsDataKey];
}

- (NSString *)syncServerAuthRootsFile {
  return self.configState[kServerAuthRootsFileKey];
}

- (NSDate *)fullSyncLastSuccess {
  return self.syncState[kFullSyncLastSuccess];
}

- (void)setFullSyncLastSuccess:(NSDate *)fullSyncLastSuccess {
  self.syncState[kFullSyncLastSuccess] = fullSyncLastSuccess;
  self.ruleSyncLastSuccess = fullSyncLastSuccess;
}

- (NSDate *)ruleSyncLastSuccess {
  return self.syncState[kRuleSyncLastSuccess];
}

- (void)setRuleSyncLastSuccess:(NSDate *)ruleSyncLastSuccess {
  self.syncState[kRuleSyncLastSuccess] = ruleSyncLastSuccess;
  [self saveSyncStateToDisk];
}

- (BOOL)syncCleanRequired {
  return [self.syncState[kSyncCleanRequired] boolValue];
}

- (void)setSyncCleanRequired:(BOOL)syncCleanRequired {
  self.syncState[kSyncCleanRequired] = @(syncCleanRequired);
  [self saveSyncStateToDisk];
}

- (NSString *)machineOwner {
  NSString *machineOwner = self.configState[kMachineOwnerKey];
  if (machineOwner) return machineOwner;

  NSString *plistPath = self.configState[kMachineOwnerPlistFileKey];
  NSString *plistKey = self.configState[kMachineOwnerPlistKeyKey];
  if (plistPath && plistKey) {
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    machineOwner = [plist[plistKey] isKindOfClass:[NSString class]] ? plist[plistKey] : nil;
  }

  return machineOwner ?: @"";
}

- (NSString *)machineID {
  NSString *machineId = self.configState[kMachineIDKey];
  if (machineId) return machineId;

  NSString *plistPath = self.configState[kMachineIDPlistFileKey];
  NSString *plistKey = self.configState[kMachineIDPlistKeyKey];

  if (plistPath && plistKey) {
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    machineId = [plist[plistKey] isKindOfClass:[NSString class]] ? plist[plistKey] : nil;
  }

  return machineId.length ? machineId : [SNTSystemInfo hardwareUUID];
}

#pragma mark Private

///
///  Update the syncState. Triggers a KVO event for all dependents.
///
- (BOOL)updateSyncStateForKey:(NSString *)key value:(id)value {
  NSMutableDictionary *syncState = self.syncState.mutableCopy;
  syncState[key] = value;
  self.syncState = syncState;
  [self saveSyncStateToDisk];
  return YES;
}

///
///  Read the saved syncState.
///
- (NSMutableDictionary *)readSyncStateFromDisk {
  // Only read the sync state if a sync server is configured.
  if (!self.syncBaseURL) return nil;
  // Only santad should read this file.
  if (geteuid() != 0) return nil;
  NSMutableDictionary *syncState =
      [NSMutableDictionary dictionaryWithContentsOfFile:kSyncStateFilePath];
  for (NSString *key in syncState.allKeys) {
    if (self.syncServerKeyTypes[key] == [NSRegularExpression class]) {
      NSString *pattern = [syncState[key] isKindOfClass:[NSString class]] ? syncState[key] : nil;
      syncState[key] = [self expressionForPattern:pattern];
    } else if (![syncState[key] isKindOfClass:self.syncServerKeyTypes[key]]) {
      syncState[key] = nil;
      continue;
    }
  }
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    WEAKIFY(self);
    self.syncStateWatcher = [[SNTFileWatcher alloc] initWithFilePath:kSyncStateFilePath
                                                             handler:^(unsigned long data) {
      STRONGIFY(self);
      [self syncStateFileChanged:data];
    }];
  });
  return syncState;
}

///
///  Saves the current effective syncState to disk.
///
- (void)saveSyncStateToDisk {
  // Only save the sync state if a sync server is configured.
  if (!self.syncBaseURL) return;
  // Only santad should write to this file.
  if (geteuid() != 0) return;
  // Either remove
  NSMutableDictionary *syncState = self.syncState.mutableCopy;
  syncState[kWhitelistRegexKey] = [syncState[kWhitelistRegexKey] pattern];
  syncState[kBlacklistRegexKey] = [syncState[kBlacklistRegexKey] pattern];
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
      LOGI(@"Sync state file permissions changed, fixing.");
      chown(cPath, 0, 0);
      chmod(cPath, desired);
    }
  } else {
    NSDictionary *newSyncState = [self readSyncStateFromDisk];
    for (NSString *key in self.syncState) {
      if (((self.syncState[key] && !newSyncState[key]) ||
           (!self.syncState[key] && newSyncState[key]) ||
           (self.syncState[key] && ![self.syncState[key] isEqualTo:newSyncState[key]]))) {
        // Ignore sync url and dates
        if ([key isEqualToString:kRuleSyncLastSuccess] ||
            [key isEqualToString:kFullSyncLastSuccess]) continue;
        LOGE(@"Sync state file changed, replacing");
        [self saveSyncStateToDisk];
        return;
      }
    }
  }
}

- (void)clearSyncState {
  self.syncState = [NSMutableDictionary dictionary];
}

#pragma mark Private Defaults Methods

- (NSRegularExpression *)expressionForPattern:(NSString *)pattern {
  if (!pattern) return nil;
  if (![pattern hasPrefix:@"^"]) pattern = [@"^" stringByAppendingString:pattern];
  return [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:NULL];
}

- (NSMutableDictionary *)readForcedConfig {
  NSMutableDictionary *forcedConfig = [NSMutableDictionary dictionary];
  for (NSString *key in self.forcedConfigKeyTypes) {
    id obj = [self forcedConfigValueForKey:key];
    forcedConfig[key] = [obj isKindOfClass:self.forcedConfigKeyTypes[key]] ? obj : nil;
    // Create the regex objects now
    if (self.forcedConfigKeyTypes[key] == [NSRegularExpression class]) {
      NSString *pattern = [obj isKindOfClass:[NSString class]] ? obj : nil;
      forcedConfig[key] = [self expressionForPattern:pattern];
    }
  }
  return forcedConfig;
}

- (id)forcedConfigValueForKey:(NSString *)key {
  id obj = [self.defaults objectForKey:key];
  return [self.defaults objectIsForcedForKey:key inDomain:kMobileConfigDomain] ? obj : nil;
}

- (void)startWatchingDefaults {
  // Only santad should listen.
  if (geteuid() != 0) return;
  [[NSNotificationCenter defaultCenter] addObserver:self
                                           selector:@selector(defaultsChanged:)
                                               name:NSUserDefaultsDidChangeNotification
                                             object:nil];
}

- (void)defaultsChanged:(void *)v {
  SEL handleChange = @selector(handleChange);
  [NSObject cancelPreviousPerformRequestsWithTarget:self selector:handleChange object:nil];
  [self performSelector:handleChange withObject:nil afterDelay:5.0f];
}

///
///  Update the configState. Triggers a KVO event for all dependents.
///
- (void)handleChange {
  self.configState = [self readForcedConfig];
}

@end
