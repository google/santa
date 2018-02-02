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
/// Creating NSRegularExpression objects is not fast, so cache them.
@property NSRegularExpression *cachedFileChangesRegex;
@property NSRegularExpression *cachedWhitelistDirRegex;
@property NSRegularExpression *cachedBlacklistDirRegex;

/// A NSUserDefaults object set to use the com.google.santa suite.
@property(readonly, nonatomic) NSUserDefaults *defaults;

/// Holds the configuration from a sync server.
@property(nonatomic, readonly) NSMutableDictionary *syncState;

/// Used to determine if the underlying values have changed.
@property SNTClientMode clientModeLastSeen;
@property NSURL *syncBaseURLLastSeen;

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
    _defaults = [NSUserDefaults standardUserDefaults];
    [_defaults addSuiteNamed:@"com.google.santa"];
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

#pragma mark Public Interface

- (SNTClientMode)clientModeAndUpdateLastSeen:(BOOL)update {
  NSInteger cm = SNTClientModeUnknown;

  NSNumber *mode = self.syncState[kClientModeKey];
  if (!mode) mode = [self forcedConfigNumberForKey:kClientModeKey];
  if ([mode respondsToSelector:@selector(longLongValue)]) cm = (NSInteger)[mode longLongValue];
  if (cm == SNTClientModeMonitor || cm == SNTClientModeLockdown) {
    if (update) self.clientModeLastSeen = cm;
    return cm;
  }

  LOGE(@"Client mode was set to bad value: %ld. Defaulting to MONITOR.", cm);
  if (update) self.clientModeLastSeen = cm;
  return SNTClientModeMonitor;
}

- (SNTClientMode)clientMode {
  return [self clientModeAndUpdateLastSeen:YES];
}

- (void)setClientMode:(SNTClientMode)newMode {
  if (newMode == SNTClientModeMonitor || newMode == SNTClientModeLockdown) {
    self.syncState[kClientModeKey] = @(newMode);
    [self saveSyncStateToDisk];
  } else {
    LOGW(@"Ignoring request to change client mode to %ld", newMode);
  }
}

- (NSURL *)syncBaseURLAndUpdateLastSeen:(BOOL)update {
  NSString *urlString = [self forcedConfigStringForKey:kSyncBaseURLKey];
  NSURL *url = [NSURL URLWithString:urlString];
  if (urlString && !url) LOGW(@"SyncBaseURL is not a valid URL!");
  if (update) self.syncBaseURLLastSeen = url;
  return url;
}

- (NSURL *)syncBaseURL {
  return [self syncBaseURLAndUpdateLastSeen:YES];
}

- (NSRegularExpression *)whitelistPathRegexUseCache:(BOOL)useCache {
  if (useCache && self.cachedWhitelistDirRegex) return self.cachedWhitelistDirRegex;

  NSString *pattern = self.syncState[kWhitelistRegexKey];
  if (!pattern) pattern = [self forcedConfigStringForKey:kWhitelistRegexKey];
  if (!pattern) return nil;
  if (![pattern hasPrefix:@"^"]) pattern = [@"^" stringByAppendingString:pattern];
  NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                      options:0
                                                                        error:NULL];
  if (useCache) self.cachedWhitelistDirRegex = re;
  return re;
}

- (NSRegularExpression *)whitelistPathRegex {
  return [self whitelistPathRegexUseCache:YES];
}

- (void)setWhitelistPathRegex:(NSRegularExpression *)re {
  self.cachedWhitelistDirRegex = nil;
  self.syncState[kWhitelistRegexKey] = [re pattern];
  [self saveSyncStateToDisk];
}

- (NSRegularExpression *)blacklistPathRegexUseCache:(BOOL)useCache {
  if (useCache && self.cachedBlacklistDirRegex) return self.cachedBlacklistDirRegex;

  NSString *pattern = self.syncState[kBlacklistRegexKey];
  if (!pattern) pattern = [self forcedConfigStringForKey:kBlacklistRegexKey];
  if (!pattern) return nil;
  if (![pattern hasPrefix:@"^"]) pattern = [@"^" stringByAppendingString:pattern];
  NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                      options:0
                                                                        error:NULL];
  if (useCache) self.cachedBlacklistDirRegex = re;
  return re;
}

- (NSRegularExpression *)blacklistPathRegex {
  return [self blacklistPathRegexUseCache:YES];
}

- (void)setBlacklistPathRegex:(NSRegularExpression *)re {
  self.cachedBlacklistDirRegex = nil;
  self.syncState[kBlacklistRegexKey] = [re pattern];
  [self saveSyncStateToDisk];
}

// Not set by the sync server but still cached for speed.
- (NSRegularExpression *)fileChangesRegexUseCache:(BOOL)useCache {
  if (useCache && self.cachedFileChangesRegex) return self.cachedFileChangesRegex;

  NSString *pattern = [self forcedConfigStringForKey:kFileChangesRegexKey];
  if (!pattern) return nil;
  if (![pattern hasPrefix:@"^"]) pattern = [@"^" stringByAppendingString:pattern];
  NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                      options:0
                                                                        error:NULL];
  if (useCache) self.cachedFileChangesRegex = re;
  return re;
}

- (NSRegularExpression *)fileChangesRegex {
  return [self fileChangesRegexUseCache:YES];
}

- (BOOL)enablePageZeroProtection {
  NSNumber *number = [self forcedConfigNumberForKey:kEnablePageZeroProtectionKey];
  return number ? [number boolValue] : YES;
}

- (NSURL *)moreInfoURL {
  return [NSURL URLWithString:[self forcedConfigStringForKey:kMoreInfoURLKey]];
}

- (NSString *)eventDetailURL {
  return [self forcedConfigStringForKey:kEventDetailURLKey];
}

- (NSString *)eventDetailText {
  return [self forcedConfigStringForKey:kEventDetailTextKey];
}

- (NSString *)unknownBlockMessage {
  return [self forcedConfigStringForKey:kUnknownBlockMessage];
}

- (NSString *)bannedBlockMessage {
  return [self forcedConfigStringForKey:kBannedBlockMessage];
}

- (NSString *)modeNotificationMonitor {
  return [self forcedConfigStringForKey:kModeNotificationMonitor];
}

- (NSString *)modeNotificationLockdown {
  return [self forcedConfigStringForKey:kModeNotificationLockdown];
}

- (NSString *)syncClientAuthCertificateFile {
  return [self forcedConfigStringForKey:kClientAuthCertificateFileKey];
}

- (NSString *)syncClientAuthCertificatePassword {
  return [self forcedConfigStringForKey:kClientAuthCertificatePasswordKey];
}

- (NSString *)syncClientAuthCertificateCn {
  return [self forcedConfigStringForKey:kClientAuthCertificateCNKey];
}

- (NSString *)syncClientAuthCertificateIssuer {
  return [self forcedConfigStringForKey:kClientAuthCertificateIssuerKey];
}

- (NSData *)syncServerAuthRootsData {
  return [self forcedConfigDataForKey:kServerAuthRootsDataKey];
}

- (NSString *)syncServerAuthRootsFile {
  return [self forcedConfigStringForKey:kServerAuthRootsFileKey];
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
  NSString *machineOwner = [self forcedConfigStringForKey:kMachineOwnerKey];
  if (machineOwner) return machineOwner;

  NSString *plistPath = [self forcedConfigStringForKey:kMachineOwnerPlistFileKey];
  NSString *plistKey = [self forcedConfigStringForKey:kMachineOwnerPlistKeyKey];
  if (plistPath && plistKey) {
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    machineOwner = [plist[plistKey] isKindOfClass:[NSString class]] ? plist[plistKey] : nil;
  }

  return machineOwner ?: @"";
}

- (NSString *)machineID {
  NSString *machineId = [self forcedConfigStringForKey:kMachineIDKey];
  if (machineId) return machineId;

  NSString *plistPath = [self forcedConfigStringForKey:kMachineIDPlistFileKey];
  NSString *plistKey = [self forcedConfigStringForKey:kMachineIDPlistKeyKey];

  if (plistPath && plistKey) {
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    machineId = [plist[plistKey] isKindOfClass:[NSString class]] ? plist[plistKey] : nil;
  }

  return [machineId length] ? machineId : [SNTSystemInfo hardwareUUID];
}

#pragma mark Private

///
///  Read the saved syncState.
///
- (NSMutableDictionary *)readSyncStateFromDisk {
  NSMutableDictionary *syncState =
      [NSMutableDictionary dictionaryWithContentsOfFile:kSyncStateFilePath];
  if (!syncState) LOGE(@"Could not read sync state file: %@", kSyncStateFilePath);
  if (geteuid() == 0) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
      WEAKIFY(self);
      self.syncStateWatcher = [[SNTFileWatcher alloc] initWithFilePath:kSyncStateFilePath
                                                               handler:^(unsigned long data) {
        STRONGIFY(self);
        [self syncStateFileChanged:data];
      }];
    });
  }
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
  [self.syncState writeToFile:kSyncStateFilePath atomically:YES];
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

#pragma mark Private Defaults Methods

- (NSData *)forcedConfigDataForKey:(NSString *)key {
  id obj = [self forcedConfigValueForKey:key];
  return [obj isKindOfClass:[NSData class]] ? obj : nil;
}

- (NSNumber *)forcedConfigNumberForKey:(NSString *)key {
  id obj = [self forcedConfigValueForKey:key];
  return [obj isKindOfClass:[NSNumber class]] ? obj : nil;
}

- (NSString *)forcedConfigStringForKey:(NSString *)key {
  id obj = [self forcedConfigValueForKey:key];
  return [obj isKindOfClass:[NSString class]] ? obj : nil;
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

- (void)handleChange {
  SNTClientMode newMode = [self clientModeAndUpdateLastSeen:NO];
  if (newMode != self.clientModeLastSeen) {
    self.clientModeLastSeen = newMode;
    if ([self.delegate conformsToProtocol:@protocol(SNTConfiguratorReceiver)]) {
      [self.delegate clientModeDidChange:newMode];
    }
  }
  NSURL *newSyncBaseURL = [self syncBaseURLAndUpdateLastSeen:NO];
  if (![newSyncBaseURL.absoluteString isEqualToString:self.syncBaseURLLastSeen.absoluteString]) {
    self.syncBaseURLLastSeen = newSyncBaseURL;
    if ([self.delegate conformsToProtocol:@protocol(SNTConfiguratorReceiver)]) {
      [self.delegate syncBaseURLDidChange:newSyncBaseURL];
    }
  }
  NSRegularExpression *newWP = [self whitelistPathRegexUseCache:NO];
  if (![newWP.pattern isEqualToString:self.cachedWhitelistDirRegex.pattern]) {
    self.cachedWhitelistDirRegex = nil;
  }
  NSRegularExpression *newBP = [self blacklistPathRegexUseCache:NO];
  if (![newBP.pattern isEqualToString:self.cachedBlacklistDirRegex.pattern]) {
    self.cachedBlacklistDirRegex = nil;
  }
  NSRegularExpression *newFP = [self fileChangesRegexUseCache:NO];
  if (![newFP.pattern isEqualToString:self.cachedFileChangesRegex.pattern]) {
    self.cachedFileChangesRegex = nil;
  }
}

@end
