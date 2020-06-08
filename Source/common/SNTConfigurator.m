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

#import "Source/common/SNTConfigurator.h"

#include <sys/stat.h>

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTSystemInfo.h"

@interface SNTConfigurator ()
/// A NSUserDefaults object set to use the com.google.santa suite.
@property(readonly, nonatomic) NSUserDefaults *defaults;

// Keys and expected value types.
@property(readonly, nonatomic) NSDictionary *syncServerKeyTypes;
@property(readonly, nonatomic) NSDictionary *forcedConfigKeyTypes;

/// Holds the configurations from a sync server and mobileconfig.
@property NSMutableDictionary *syncState;
@property NSMutableDictionary *configState;
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
static NSString *const kEnableBadSignatureProtectionKey = @"EnableBadSignatureProtection";

static NSString *const kFileChangesRegexKey = @"FileChangesRegex";
static NSString *const kFileChangesPrefixFiltersKey = @"FileChangesPrefixFilters";

static NSString *const kEventLogType = @"EventLogType";
static NSString *const kEventLogPath = @"EventLogPath";

static NSString *const kEnableMachineIDDecoration = @"EnableMachineIDDecoration";

static NSString *const kEnableSystemExtension = @"EnableSystemExtension";

// The keys managed by a sync server or mobileconfig.
static NSString *const kClientModeKey = @"ClientMode";
static NSString *const kEnableTransitiveRulesKey = @"EnableTransitiveRules";
static NSString *const kEnableTransitiveRulesKeyDeprecated = @"EnableTransitiveWhitelisting";
static NSString *const kAllowedPathRegexKey = @"AllowedPathRegex";
static NSString *const kAllowedPathRegexKeyDeprecated = @"WhitelistRegex";
static NSString *const kBlockedPathRegexKey = @"BlockedPathRegex";
static NSString *const kBlockedPathRegexKeyDeprecated = @"BlacklistRegex";

// The keys managed by a sync server.
static NSString *const kFullSyncLastSuccess = @"FullSyncLastSuccess";
static NSString *const kRuleSyncLastSuccess = @"RuleSyncLastSuccess";
static NSString *const kSyncCleanRequired = @"SyncCleanRequired";

- (instancetype)init {
  self = [super init];
  if (self) {
    Class number = [NSNumber class];
    Class re = [NSRegularExpression class];
    Class date = [NSDate class];
    Class string = [NSString class];
    Class data = [NSData class];
    Class array = [NSArray class];
    _syncServerKeyTypes = @{
      kClientModeKey : number,
      kEnableTransitiveRulesKey : number,
      kEnableTransitiveRulesKeyDeprecated : number,
      kAllowedPathRegexKey : re,
      kAllowedPathRegexKeyDeprecated : re,
      kBlockedPathRegexKey : re,
      kBlockedPathRegexKeyDeprecated : re,
      kFullSyncLastSuccess : date,
      kRuleSyncLastSuccess : date,
      kSyncCleanRequired : number
    };
    _forcedConfigKeyTypes = @{
      kClientModeKey : number,
      kEnableTransitiveRulesKey : number,
      kEnableTransitiveRulesKeyDeprecated : number,
      kFileChangesRegexKey : re,
      kFileChangesPrefixFiltersKey : array,
      kAllowedPathRegexKey : re,
      kAllowedPathRegexKeyDeprecated : re,
      kBlockedPathRegexKey : re,
      kBlockedPathRegexKeyDeprecated : re,
      kEnablePageZeroProtectionKey : number,
      kEnableBadSignatureProtectionKey: number,
      kMoreInfoURLKey : string,
      kEventDetailURLKey : string,
      kEventDetailTextKey : string,
      kUnknownBlockMessage : string,
      kBannedBlockMessage : string,
      kModeNotificationMonitor : string,
      kModeNotificationLockdown : string,
      kSyncBaseURLKey : string,
      kClientAuthCertificateFileKey : string,
      kClientAuthCertificatePasswordKey : string,
      kClientAuthCertificateCNKey : string,
      kClientAuthCertificateIssuerKey : string,
      kServerAuthRootsDataKey  : data,
      kServerAuthRootsFileKey : string,
      kMachineOwnerKey : string,
      kMachineIDKey : string,
      kMachineOwnerPlistFileKey : string,
      kMachineOwnerPlistKeyKey : string,
      kMachineIDPlistFileKey : string,
      kMachineIDPlistKeyKey : string,
      kEventLogType : string,
      kEventLogPath : string,
      kEnableMachineIDDecoration : number,
      kEnableSystemExtension : number,
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

+ (NSSet *)syncAndConfigStateSet {
  static NSSet *set;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    set = [[self syncStateSet] setByAddingObjectsFromSet:[self configStateSet]];
  });
  return set;
}

+ (NSSet *)syncStateSet {
  static NSSet *set;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    set = [NSSet setWithObject:NSStringFromSelector(@selector(syncState))];
  });
  return set;
}

+ (NSSet *)configStateSet {
  static NSSet *set;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    set = [NSSet setWithObject:NSStringFromSelector(@selector(configState))];
  });
  return set;
}

#pragma mark KVO Dependencies

+ (NSSet *)keyPathsForValuesAffectingClientMode {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingAllowlistPathRegex {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingBlocklistPathRegex {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileChangesRegex {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileChangesPrefixFiltersKey {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncBaseURL {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnablePageZeroProtection {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingMoreInfoURL {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEventDetailURL {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEventDetailText {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingUnknownBlockMessage {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingBannedBlockMessage {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingModeNotificationMonitor {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingModeNotificationLockdown {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncClientAuthCertificateFile {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncClientAuthCertificatePassword {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncClientAuthCertificateCn {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncClientAuthCertificateIssuer {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncServerAuthRootsData {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncServerAuthRootsFile {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingMachineOwner {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingMachineID {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFullSyncLastSuccess {
  return [self syncStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingRuleSyncLastSuccess {
  return [self syncStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncCleanRequired {
  return [self syncStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEventLogType {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEventLogPath {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableMachineIDDecoration {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableTransitiveRules {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableSystemExtension {
  return [self configStateSet];
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

- (BOOL)enableTransitiveRules {
  NSNumber *n = self.syncState[kEnableTransitiveRulesKey];
  if (n) return [n boolValue];

  n = self.syncState[kEnableTransitiveRulesKeyDeprecated];
  if (n) return [n boolValue];

  n = self.configState[kEnableTransitiveRulesKeyDeprecated];
  if (n) return [n boolValue];

  return [self.configState[kEnableTransitiveRulesKey] boolValue];
}

- (void)setEnableTransitiveRules:(BOOL)enabled {
  [self updateSyncStateForKey:kEnableTransitiveRulesKey value:@(enabled)];
}

- (NSRegularExpression *)allowedPathRegex {
  NSRegularExpression *r = self.syncState[kAllowedPathRegexKey];
  if (r) return r;

  r = self.syncState[kAllowedPathRegexKeyDeprecated];
  if (r) return r;

  r = self.configState[kAllowedPathRegexKey];
  if (r) return r;

  return self.configState[kAllowedPathRegexKeyDeprecated];
}

- (void)setSyncServerAllowedPathRegex:(NSRegularExpression *)re {
  [self updateSyncStateForKey:kAllowedPathRegexKey value:re];
}

- (NSRegularExpression *)blockedPathRegex {
  NSRegularExpression *r = self.syncState[kBlockedPathRegexKey];
  if (r) return r;

  r = self.syncState[kBlockedPathRegexKeyDeprecated];
  if (r) return r;

  r = self.configState[kBlockedPathRegexKey];
  if (r) return r;

  return self.configState[kBlockedPathRegexKeyDeprecated];
}

- (void)setSyncServerBlockedPathRegex:(NSRegularExpression *)re {
  [self updateSyncStateForKey:kBlockedPathRegexKey value:re];
}

- (NSRegularExpression *)fileChangesRegex {
  return self.configState[kFileChangesRegexKey];
}

- (NSArray *)fileChangesPrefixFilters {
  NSArray *filters = self.configState[kFileChangesPrefixFiltersKey];
  for (id filter in filters) {
    if (![filter isKindOfClass:[NSString class]]) {
      LOGE(@"Ignoring FileChangesPrefixFilters: array contains a non-string %@", filter);
      return nil;
    }
  }
  return filters;
}

- (NSURL *)syncBaseURL {
  NSString *urlString = self.configState[kSyncBaseURLKey];
  if (![urlString hasSuffix:@"/"]) urlString = [urlString stringByAppendingString:@"/"];
  NSURL *url = [NSURL URLWithString:urlString];
  if (urlString && !url) LOGW(@"SyncBaseURL is not a valid URL!");
  return url;
}

- (BOOL)enablePageZeroProtection {
  NSNumber *number = self.configState[kEnablePageZeroProtectionKey];
  return number ? [number boolValue] : YES;
}

- (BOOL)enableBadSignatureProtection {
  NSNumber *number = self.configState[kEnableBadSignatureProtectionKey];
  return number ? [number boolValue] : NO;
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
  [self updateSyncStateForKey:kFullSyncLastSuccess value:fullSyncLastSuccess];
  self.ruleSyncLastSuccess = fullSyncLastSuccess;
}

- (NSDate *)ruleSyncLastSuccess {
  return self.syncState[kRuleSyncLastSuccess];
}

- (void)setRuleSyncLastSuccess:(NSDate *)ruleSyncLastSuccess {
  [self updateSyncStateForKey:kRuleSyncLastSuccess value:ruleSyncLastSuccess];
}

- (BOOL)syncCleanRequired {
  return [self.syncState[kSyncCleanRequired] boolValue];
}

- (void)setSyncCleanRequired:(BOOL)syncCleanRequired {
  [self updateSyncStateForKey:kSyncCleanRequired value:@(syncCleanRequired)];
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

- (SNTEventLogType)eventLogType {
  NSString *s = [self.configState[kEventLogType] lowercaseString];
  return [s isEqualToString:@"syslog"] ? SNTEventLogTypeSyslog : SNTEventLogTypeFilelog;
}

- (NSString *)eventLogPath {
  return self.configState[kEventLogPath] ?: @"/var/db/santa/santa.log";
}

- (BOOL)enableMachineIDDecoration {
  NSNumber *number = self.configState[kEnableMachineIDDecoration];
  return number ? [number boolValue] : NO;
}

- (BOOL)enableSystemExtension {
  if (@available(macOS 10.15, *)) {
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:@"/Library/Extensions/santa-driver.kext"]) return YES;
    NSNumber *number = self.configState[kEnableSystemExtension];
    return number ? [number boolValue] : YES;
  } else {
    return NO;
  }
}

#pragma mark Private

///
///  Update the syncState. Triggers a KVO event for all dependents.
///
- (void)updateSyncStateForKey:(NSString *)key value:(id)value {
  dispatch_async(dispatch_get_main_queue(), ^{
    NSMutableDictionary *syncState = self.syncState.mutableCopy;
    syncState[key] = value;
    self.syncState = syncState;
    [self saveSyncStateToDisk];
  });
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
  syncState[kAllowedPathRegexKey] = [syncState[kAllowedPathRegexKey] pattern];
  syncState[kBlockedPathRegexKey] = [syncState[kBlockedPathRegexKey] pattern];
  [syncState writeToFile:kSyncStateFilePath atomically:YES];
  [[NSFileManager defaultManager] setAttributes:@{ NSFilePosixPermissions : @0644 }
                                   ofItemAtPath:kSyncStateFilePath error:NULL];
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
  // Only com.google.santa.daemon should listen.
  NSString *processName = [[NSProcessInfo processInfo] processName];
  if (![processName isEqualToString:@"com.google.santa.daemon"]) return;
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
