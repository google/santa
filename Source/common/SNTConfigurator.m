/// Copyright 2014-2022 Google Inc. All rights reserved.
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

#import "Source/common/SNTRule.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTSystemInfo.h"

// Ensures the given object is an NSArray and only contains NSString value types
static NSArray<NSString *> *EnsureArrayOfStrings(id obj) {
  if (![obj isKindOfClass:[NSArray class]]) {
    return nil;
  }

  for (id item in obj) {
    if (![item isKindOfClass:[NSString class]]) {
      return nil;
    }
  }

  return obj;
}

@interface SNTConfigurator ()
/// A NSUserDefaults object set to use the com.google.santa suite.
@property(readonly, nonatomic) NSUserDefaults *defaults;

/// Keys and expected value types.
@property(readonly, nonatomic) NSDictionary *syncServerKeyTypes;
@property(readonly, nonatomic) NSDictionary *forcedConfigKeyTypes;

/// Holds the configurations from a sync server and mobileconfig.
@property NSDictionary *syncState;
@property NSMutableDictionary *configState;

/// Was --debug passed as an argument to this process?
@property(readonly, nonatomic) BOOL debugFlag;

/// Holds the last processed hash of the static rules list.
@property(atomic) NSDictionary *cachedStaticRules;

@property(readonly, nonatomic) NSString *syncStateFilePath;
@property(nonatomic, copy) BOOL (^syncStateAccessAuthorizerBlock)();

@end

@implementation SNTConfigurator

/// The hard-coded path to the sync state file.
NSString *const kSyncStateFilePath = @"/var/db/santa/sync-state.plist";

#ifdef DEBUG
NSString *const kConfigOverrideFilePath = @"/var/db/santa/config-overrides.plist";
#endif

/// The domain used by mobileconfig.
static NSString *const kMobileConfigDomain = @"com.google.santa";

/// The keys managed by a mobileconfig.
static NSString *const kStaticRules = @"StaticRules";
static NSString *const kSyncBaseURLKey = @"SyncBaseURL";
static NSString *const kSyncEnableProtoTransfer = @"SyncEnableProtoTransfer";
static NSString *const kSyncProxyConfigKey = @"SyncProxyConfiguration";
static NSString *const kSyncExtraHeadersKey = @"SyncExtraHeaders";
static NSString *const kSyncEnableCleanSyncEventUpload = @"SyncEnableCleanSyncEventUpload";
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

static NSString *const kEnableSilentModeKey = @"EnableSilentMode";
static NSString *const kEnableSilentTTYModeKey = @"EnableSilentTTYMode";
static NSString *const kAboutTextKey = @"AboutText";
static NSString *const kMoreInfoURLKey = @"MoreInfoURL";
static NSString *const kEventDetailURLKey = @"EventDetailURL";
static NSString *const kEventDetailTextKey = @"EventDetailText";
static NSString *const kDismissTextKey = @"DismissText";
static NSString *const kUnknownBlockMessage = @"UnknownBlockMessage";
static NSString *const kBannedBlockMessage = @"BannedBlockMessage";
static NSString *const kBannedUSBBlockMessage = @"BannedUSBBlockMessage";
static NSString *const kRemountUSBBlockMessage = @"RemountUSBBlockMessage";

static NSString *const kModeNotificationMonitor = @"ModeNotificationMonitor";
static NSString *const kModeNotificationLockdown = @"ModeNotificationLockdown";

static NSString *const kEnablePageZeroProtectionKey = @"EnablePageZeroProtection";
static NSString *const kEnableBadSignatureProtectionKey = @"EnableBadSignatureProtection";
static NSString *const kFailClosedKey = @"FailClosed";
static NSString *const kDisableUnknownEventUploadKey = @"DisableUnknownEventUpload";

static NSString *const kFileChangesRegexKey = @"FileChangesRegex";
static NSString *const kFileChangesPrefixFiltersKey = @"FileChangesPrefixFilters";

static NSString *const kEventLogType = @"EventLogType";
static NSString *const kEventLogPath = @"EventLogPath";
static NSString *const kSpoolDirectory = @"SpoolDirectory";
static NSString *const kSpoolDirectoryFileSizeThresholdKB = @"SpoolDirectoryFileSizeThresholdKB";
static NSString *const kSpoolDirectorySizeThresholdMB = @"SpoolDirectorySizeThresholdMB";
static NSString *const kSpoolDirectoryEventMaxFlushTimeSec = @"SpoolDirectoryEventMaxFlushTimeSec";

static NSString *const kFileAccessPolicy = @"FileAccessPolicy";
static NSString *const kFileAccessPolicyPlist = @"FileAccessPolicyPlist";
static NSString *const kFileAccessBlockMessage = @"FileAccessBlockMessage";
static NSString *const kFileAccessPolicyUpdateIntervalSec = @"FileAccessPolicyUpdateIntervalSec";

static NSString *const kEnableMachineIDDecoration = @"EnableMachineIDDecoration";

static NSString *const kEnableForkAndExitLogging = @"EnableForkAndExitLogging";
static NSString *const kIgnoreOtherEndpointSecurityClients = @"IgnoreOtherEndpointSecurityClients";
static NSString *const kEnableDebugLogging = @"EnableDebugLogging";

static NSString *const kClientContentEncoding = @"SyncClientContentEncoding";

static NSString *const kFCMProject = @"FCMProject";
static NSString *const kFCMEntity = @"FCMEntity";
static NSString *const kFCMAPIKey = @"FCMAPIKey";

static NSString *const kEntitlementsPrefixFilterKey = @"EntitlementsPrefixFilter";
static NSString *const kEntitlementsTeamIDFilterKey = @"EntitlementsTeamIDFilter";

static NSString *const kOnStartUSBOptions = @"OnStartUSBOptions";

static NSString *const kMetricFormat = @"MetricFormat";
static NSString *const kMetricURL = @"MetricURL";
static NSString *const kMetricExportInterval = @"MetricExportInterval";
static NSString *const kMetricExportTimeout = @"MetricExportTimeout";
static NSString *const kMetricExtraLabels = @"MetricExtraLabels";

static NSString *const kEnabledProcessAnnotations = @"EnabledProcessAnnotations";

// The keys managed by a sync server or mobileconfig.
static NSString *const kClientModeKey = @"ClientMode";
static NSString *const kBlockUSBMountKey = @"BlockUSBMount";
static NSString *const kRemountUSBModeKey = @"RemountUSBMode";
static NSString *const kEnableTransitiveRulesKey = @"EnableTransitiveRules";
static NSString *const kEnableTransitiveRulesKeyDeprecated = @"EnableTransitiveWhitelisting";
static NSString *const kAllowedPathRegexKey = @"AllowedPathRegex";
static NSString *const kAllowedPathRegexKeyDeprecated = @"WhitelistRegex";
static NSString *const kBlockedPathRegexKey = @"BlockedPathRegex";
static NSString *const kBlockedPathRegexKeyDeprecated = @"BlacklistRegex";
static NSString *const kEnableAllEventUploadKey = @"EnableAllEventUpload";
static NSString *const kOverrideFileAccessActionKey = @"OverrideFileAccessAction";

// The keys managed by a sync server.
static NSString *const kFullSyncLastSuccess = @"FullSyncLastSuccess";
static NSString *const kRuleSyncLastSuccess = @"RuleSyncLastSuccess";
static NSString *const kSyncCleanRequiredDeprecated = @"SyncCleanRequired";
static NSString *const kSyncTypeRequired = @"SyncTypeRequired";

- (instancetype)init {
  return [self initWithSyncStateFile:kSyncStateFilePath
           syncStateAccessAuthorizer:^BOOL() {
             // Only access the sync state if a sync server is configured and running as root
             return self.syncBaseURL != nil && geteuid() == 0;
           }];
}

- (instancetype)initWithSyncStateFile:(NSString *)syncStateFilePath
            syncStateAccessAuthorizer:(BOOL (^)(void))syncStateAccessAuthorizer {
  self = [super init];
  if (self) {
    Class number = [NSNumber class];
    Class re = [NSRegularExpression class];
    Class date = [NSDate class];
    Class string = [NSString class];
    Class data = [NSData class];
    Class array = [NSArray class];
    Class dictionary = [NSDictionary class];
    _syncServerKeyTypes = @{
      kClientModeKey : number,
      kEnableTransitiveRulesKey : number,
      kEnableTransitiveRulesKeyDeprecated : number,
      kAllowedPathRegexKey : re,
      kAllowedPathRegexKeyDeprecated : re,
      kBlockedPathRegexKey : re,
      kBlockedPathRegexKeyDeprecated : re,
      kBlockUSBMountKey : number,
      kRemountUSBModeKey : array,
      kFullSyncLastSuccess : date,
      kRuleSyncLastSuccess : date,
      kSyncCleanRequiredDeprecated : number,
      kSyncTypeRequired : number,
      kEnableAllEventUploadKey : number,
      kOverrideFileAccessActionKey : string,
    };
    _forcedConfigKeyTypes = @{
      kClientModeKey : number,
      kFailClosedKey : number,
      kEnableTransitiveRulesKey : number,
      kEnableTransitiveRulesKeyDeprecated : number,
      kFileChangesRegexKey : re,
      kFileChangesPrefixFiltersKey : array,
      kAllowedPathRegexKey : re,
      kAllowedPathRegexKeyDeprecated : re,
      kBlockedPathRegexKey : re,
      kBlockedPathRegexKeyDeprecated : re,
      kBlockUSBMountKey : number,
      kRemountUSBModeKey : array,
      kOnStartUSBOptions : string,
      kEnablePageZeroProtectionKey : number,
      kEnableBadSignatureProtectionKey : number,
      kEnableSilentModeKey : number,
      kEnableSilentTTYModeKey : number,
      kAboutTextKey : string,
      kMoreInfoURLKey : string,
      kEventDetailURLKey : string,
      kEventDetailTextKey : string,
      kDismissTextKey : string,
      kUnknownBlockMessage : string,
      kBannedBlockMessage : string,
      kBannedUSBBlockMessage : string,
      kRemountUSBBlockMessage : string,
      kModeNotificationMonitor : string,
      kModeNotificationLockdown : string,
      kStaticRules : array,
      kSyncBaseURLKey : string,
      kSyncEnableProtoTransfer : number,
      kSyncEnableCleanSyncEventUpload : number,
      kSyncProxyConfigKey : dictionary,
      kSyncExtraHeadersKey : dictionary,
      kClientAuthCertificateFileKey : string,
      kClientAuthCertificatePasswordKey : string,
      kClientAuthCertificateCNKey : string,
      kClientAuthCertificateIssuerKey : string,
      kClientContentEncoding : string,
      kServerAuthRootsDataKey : data,
      kServerAuthRootsFileKey : string,
      kMachineOwnerKey : string,
      kMachineIDKey : string,
      kMachineOwnerPlistFileKey : string,
      kMachineOwnerPlistKeyKey : string,
      kMachineIDPlistFileKey : string,
      kMachineIDPlistKeyKey : string,
      kEventLogType : string,
      kEventLogPath : string,
      kSpoolDirectory : string,
      kSpoolDirectoryFileSizeThresholdKB : number,
      kSpoolDirectorySizeThresholdMB : number,
      kSpoolDirectoryEventMaxFlushTimeSec : number,
      kFileAccessPolicy : dictionary,
      kFileAccessPolicyPlist : string,
      kFileAccessBlockMessage : string,
      kFileAccessPolicyUpdateIntervalSec : number,
      kEnableMachineIDDecoration : number,
      kEnableForkAndExitLogging : number,
      kIgnoreOtherEndpointSecurityClients : number,
      kEnableDebugLogging : number,
      kFCMProject : string,
      kFCMEntity : string,
      kFCMAPIKey : string,
      kMetricFormat : string,
      kMetricURL : string,
      kMetricExportInterval : number,
      kMetricExportTimeout : number,
      kMetricExtraLabels : dictionary,
      kEnableAllEventUploadKey : number,
      kDisableUnknownEventUploadKey : number,
      kOverrideFileAccessActionKey : string,
      kEntitlementsPrefixFilterKey : array,
      kEntitlementsTeamIDFilterKey : array,
      kEnabledProcessAnnotations : array,
    };

    _syncStateFilePath = syncStateFilePath;
    _syncStateAccessAuthorizerBlock = syncStateAccessAuthorizer;

    _defaults = [NSUserDefaults standardUserDefaults];
    [_defaults addSuiteNamed:@"com.google.santa"];
    _configState = [self readForcedConfig];
    [self cacheStaticRules];

    _syncState = [self readSyncStateFromDisk] ?: [NSMutableDictionary dictionary];
    if ([self migrateDeprecatedSyncStateKeys]) {
      // Save the updated sync state if any keys were migrated.
      [self saveSyncStateToDisk];
    }

    _debugFlag = [[NSProcessInfo processInfo].arguments containsObject:@"--debug"];
    [self startWatchingDefaults];
  }
  return self;
}

#pragma mark Singleton retriever

// The returned value is marked unsafe_unretained to avoid unnecessary retain/release handling.
// The object returned is guaranteed to exist for the lifetime of the process so there's no need
// to do this handling.
+ (__unsafe_unretained instancetype)configurator {
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

+ (NSSet *)keyPathsForValuesAffectingStaticRules {
  static NSSet *set;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    set = [NSSet setWithObject:NSStringFromSelector(@selector(cachedStaticRules))];
  });
  return set;
}

+ (NSSet *)keyPathsForValuesAffectingSyncBaseURL {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncEnableProtoTransfer {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncExtraHeaders {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableCleanSyncEventUpload {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnablePageZeroProtection {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableSilentMode {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingAboutText {
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

+ (NSSet *)keyPathsForValuesAffectingDismissText {
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

+ (NSSet *)keyPathsForValuesAffectingSyncTypeRequired {
  return [self syncStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEventLogType {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEventLogPath {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSpoolDirectory {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSpoolDirectoryFileSizeThresholdKB {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSpoolDirectorySizeThresholdMB {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSpoolDirectoryEventMaxFlushTimeSec {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileAccessPolicy {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileAccessPolicyPlist {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileAccessBlockMessage {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileAccessPolicyUpdateIntervalSec {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableMachineIDDecoration {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableTransitiveRules {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableAllEventUpload {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingDisableUnknownEventUpload {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableForkAndExitLogging {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingIgnoreOtherEndpointSecurityClients {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableDebugLogging {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFcmProject {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFcmEntity {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFcmAPIKey {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFcmEnabled {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableBadSignatureProtection {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingBlockUSBMount {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingBannedUSBBlockMessage {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingRemountUSBMode {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingRemountUSBBlockMessage {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingUsbBlockMessage {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingOverrideFileAccessActionKey {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEntitlementsPrefixFilter {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEntitlementsTeamIDFilter {
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
  }
}

- (BOOL)failClosed {
  NSNumber *n = self.configState[kFailClosedKey];
  return [n boolValue] && self.clientMode == SNTClientModeLockdown;
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
      return nil;
    }
  }
  return filters;
}

- (void)setRemountUSBMode:(NSArray<NSString *> *)args {
  [self updateSyncStateForKey:kRemountUSBModeKey value:args];
}

- (NSArray<NSString *> *)remountUSBMode {
  NSArray<NSString *> *args = self.syncState[kRemountUSBModeKey];
  if (!args) {
    args = (NSArray<NSString *> *)self.configState[kRemountUSBModeKey];
  }
  for (id arg in args) {
    if (![arg isKindOfClass:[NSString class]]) {
      return nil;
    }
  }
  return args;
}

- (SNTDeviceManagerStartupPreferences)onStartUSBOptions {
  NSString *action = [self.configState[kOnStartUSBOptions] lowercaseString];

  if ([action isEqualToString:@"unmount"]) {
    return SNTDeviceManagerStartupPreferencesUnmount;
  } else if ([action isEqualToString:@"forceunmount"]) {
    return SNTDeviceManagerStartupPreferencesForceUnmount;
  } else if ([action isEqualToString:@"remount"]) {
    return SNTDeviceManagerStartupPreferencesRemount;
  } else if ([action isEqualToString:@"forceremount"]) {
    return SNTDeviceManagerStartupPreferencesForceRemount;
  } else {
    return SNTDeviceManagerStartupPreferencesNone;
  }
}

- (NSDictionary<NSString *, SNTRule *> *)staticRules {
  return self.cachedStaticRules;
}

- (NSURL *)syncBaseURL {
  NSString *urlString = self.configState[kSyncBaseURLKey];
  if (![urlString hasSuffix:@"/"]) urlString = [urlString stringByAppendingString:@"/"];
  NSURL *url = [NSURL URLWithString:urlString];
  return url;
}

- (BOOL)syncEnableProtoTransfer {
  NSNumber *number = self.configState[kSyncEnableProtoTransfer];
  return number ? [number boolValue] : NO;
}

- (NSDictionary *)syncProxyConfig {
  return self.configState[kSyncProxyConfigKey];
}

- (NSDictionary *)syncExtraHeaders {
  return self.configState[kSyncExtraHeadersKey];
}

- (BOOL)enablePageZeroProtection {
  NSNumber *number = self.configState[kEnablePageZeroProtectionKey];
  return number ? [number boolValue] : YES;
}

- (BOOL)enableBadSignatureProtection {
  NSNumber *number = self.configState[kEnableBadSignatureProtectionKey];
  return number ? [number boolValue] : NO;
}

- (BOOL)enableSilentMode {
  NSNumber *number = self.configState[kEnableSilentModeKey];
  return number ? [number boolValue] : NO;
}

- (BOOL)enableSilentTTYMode {
  NSNumber *number = self.configState[kEnableSilentTTYModeKey];
  return number ? [number boolValue] : NO;
}

- (NSString *)aboutText {
  return self.configState[kAboutTextKey];
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

- (NSString *)dismissText {
  return self.configState[kDismissTextKey];
}

- (NSString *)unknownBlockMessage {
  return self.configState[kUnknownBlockMessage];
}

- (NSString *)bannedBlockMessage {
  return self.configState[kBannedBlockMessage];
}

- (NSString *)bannedUSBBlockMessage {
  if (!self.configState[kBannedUSBBlockMessage]) {
    return @"The following device has been blocked from mounting.";
  }

  return self.configState[kBannedUSBBlockMessage];
}

- (NSString *)remountUSBBlockMessage {
  if (!self.configState[kRemountUSBBlockMessage]) {
    return @"The following device has been remounted with reduced permissions.";
  }
  return self.configState[kRemountUSBBlockMessage];
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

- (SNTSyncContentEncoding)syncClientContentEncoding {
  NSString *contentEncoding = [self.configState[kClientContentEncoding] lowercaseString];
  if ([contentEncoding isEqualToString:@"deflate"]) {
    return SNTSyncContentEncodingDeflate;
  } else if ([contentEncoding isEqualToString:@"gzip"]) {
    return SNTSyncContentEncodingGzip;
  } else if ([contentEncoding isEqualToString:@"none"]) {
    return SNTSyncContentEncodingNone;
  } else {
    // Ensure we have the same default zlib behavior Santa's always had otherwise.
    return SNTSyncContentEncodingDeflate;
  }
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

- (SNTSyncType)syncTypeRequired {
  return (SNTSyncType)[self.syncState[kSyncTypeRequired] integerValue];
}

- (void)setSyncTypeRequired:(SNTSyncType)syncTypeRequired {
  [self updateSyncStateForKey:kSyncTypeRequired value:@(syncTypeRequired)];
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
  NSString *logType = [self.configState[kEventLogType] lowercaseString];
  if ([logType isEqualToString:@"protobuf"]) {
    return SNTEventLogTypeProtobuf;
  } else if ([logType isEqualToString:@"syslog"]) {
    return SNTEventLogTypeSyslog;
  } else if ([logType isEqualToString:@"null"]) {
    return SNTEventLogTypeNull;
  } else if ([logType isEqualToString:@"json"]) {
    return SNTEventLogTypeJSON;
  } else if ([logType isEqualToString:@"file"]) {
    return SNTEventLogTypeFilelog;
  } else {
    return SNTEventLogTypeFilelog;
  }
}

- (NSString *)eventLogTypeRaw {
  return self.configState[kEventLogType] ?: @"file";
}

- (NSString *)eventLogPath {
  return self.configState[kEventLogPath] ?: @"/var/db/santa/santa.log";
}

- (NSString *)spoolDirectory {
  return self.configState[kSpoolDirectory] ?: @"/var/db/santa/spool";
}

- (NSUInteger)spoolDirectoryFileSizeThresholdKB {
  return self.configState[kSpoolDirectoryFileSizeThresholdKB]
           ? [self.configState[kSpoolDirectoryFileSizeThresholdKB] unsignedIntegerValue]
           : 250;
}

- (NSUInteger)spoolDirectorySizeThresholdMB {
  return self.configState[kSpoolDirectorySizeThresholdMB]
           ? [self.configState[kSpoolDirectorySizeThresholdMB] unsignedIntegerValue]
           : 100;
}

- (float)spoolDirectoryEventMaxFlushTimeSec {
  return self.configState[kSpoolDirectoryEventMaxFlushTimeSec]
           ? [self.configState[kSpoolDirectoryEventMaxFlushTimeSec] floatValue]
           : 15.0;
}

- (NSDictionary *)fileAccessPolicy {
  return self.configState[kFileAccessPolicy];
}

- (NSString *)fileAccessPolicyPlist {
  // This property is ignored when kFileAccessPolicy is set
  if (self.configState[kFileAccessPolicy]) {
    return nil;
  } else {
    return self.configState[kFileAccessPolicyPlist];
  }
}

- (NSString *)fileAccessBlockMessage {
  return self.configState[kFileAccessBlockMessage];
}

- (uint32_t)fileAccessPolicyUpdateIntervalSec {
  return self.configState[kFileAccessPolicyUpdateIntervalSec]
           ? [self.configState[kFileAccessPolicyUpdateIntervalSec] unsignedIntValue]
           : 60 * 10;
}

- (BOOL)enableMachineIDDecoration {
  NSNumber *number = self.configState[kEnableMachineIDDecoration];
  return number ? [number boolValue] : NO;
}

- (BOOL)enableCleanSyncEventUpload {
  NSNumber *number = self.configState[kSyncEnableCleanSyncEventUpload];
  return number ? [number boolValue] : NO;
}

- (BOOL)enableAllEventUpload {
  NSNumber *n = self.syncState[kEnableAllEventUploadKey];
  if (n) return [n boolValue];

  return [self.configState[kEnableAllEventUploadKey] boolValue];
}

- (void)setEnableAllEventUpload:(BOOL)enabled {
  [self updateSyncStateForKey:kEnableAllEventUploadKey value:@(enabled)];
}

- (BOOL)disableUnknownEventUpload {
  NSNumber *n = self.syncState[kDisableUnknownEventUploadKey];
  if (n) return [n boolValue];

  return [self.configState[kDisableUnknownEventUploadKey] boolValue];
}

- (void)setDisableUnknownEventUpload:(BOOL)enabled {
  [self updateSyncStateForKey:kDisableUnknownEventUploadKey value:@(enabled)];
}

- (BOOL)enableForkAndExitLogging {
  NSNumber *number = self.configState[kEnableForkAndExitLogging];
  return number ? [number boolValue] : NO;
}

- (BOOL)ignoreOtherEndpointSecurityClients {
  NSNumber *number = self.configState[kIgnoreOtherEndpointSecurityClients];
  return number ? [number boolValue] : NO;
}

- (BOOL)enableDebugLogging {
  NSNumber *number = self.configState[kEnableDebugLogging];
  return [number boolValue] || self.debugFlag;
}

- (NSString *)fcmProject {
  return self.configState[kFCMProject];
}

- (NSString *)fcmEntity {
  return self.configState[kFCMEntity];
}

- (NSString *)fcmAPIKey {
  return self.configState[kFCMAPIKey];
}

- (BOOL)fcmEnabled {
  return (self.fcmProject.length && self.fcmEntity.length && self.fcmAPIKey.length);
}

- (void)setBlockUSBMount:(BOOL)enabled {
  [self updateSyncStateForKey:kBlockUSBMountKey value:@(enabled)];
}

- (BOOL)blockUSBMount {
  NSNumber *n = self.syncState[kBlockUSBMountKey];
  if (n) return [n boolValue];

  return [self.configState[kBlockUSBMountKey] boolValue];
}

- (void)setSyncServerOverrideFileAccessAction:(NSString *)action {
  NSString *a = [action lowercaseString];
  if ([a isEqualToString:@"auditonly"] || [a isEqualToString:@"disable"] ||
      [a isEqualToString:@"none"] || [a isEqualToString:@""]) {
    [self updateSyncStateForKey:kOverrideFileAccessActionKey value:action];
  }
}

- (SNTOverrideFileAccessAction)overrideFileAccessAction {
  NSString *action = [self.syncState[kOverrideFileAccessActionKey] lowercaseString];

  if (!action) {
    action = [self.configState[kOverrideFileAccessActionKey] lowercaseString];
    if (!action) {
      return SNTOverrideFileAccessActionNone;
    }
  }

  // Note: `auditonly` without an underscore is a deprecated, but still accepted form.
  if ([action isEqualToString:@"audit_only"] || [action isEqualToString:@"auditonly"]) {
    return SNTOverrideFileAccessActionAuditOnly;
  } else if ([action isEqualToString:@"disable"]) {
    return SNTOverrideFileAccessActionDiable;
  } else {
    return SNTOverrideFileAccessActionNone;
  }
}

///
/// Returns YES if all of the necessary options are set to export metrics, NO
/// otherwise.
///
- (BOOL)exportMetrics {
  return [self metricFormat] != SNTMetricFormatTypeUnknown &&
         ![self.configState[kMetricURL] isEqualToString:@""];
}

- (SNTMetricFormatType)metricFormat {
  NSString *normalized = [self.configState[kMetricFormat] lowercaseString];

  normalized = [normalized stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  if ([normalized isEqualToString:@"rawjson"]) {
    return SNTMetricFormatTypeRawJSON;
  } else if ([normalized isEqualToString:@"monarchjson"]) {
    return SNTMetricFormatTypeMonarchJSON;
  } else {
    return SNTMetricFormatTypeUnknown;
  }
}

- (NSURL *)metricURL {
  return [NSURL URLWithString:self.configState[kMetricURL]];
}

// Returns a default value of 30 (for 30 seconds).
- (NSUInteger)metricExportInterval {
  NSNumber *configuredInterval = self.configState[kMetricExportInterval];

  if (configuredInterval == nil) {
    return 30;
  }
  return [configuredInterval unsignedIntegerValue];
}

// Returns a default value of 30 (for 30 seconds).
- (NSUInteger)metricExportTimeout {
  NSNumber *configuredInterval = self.configState[kMetricExportTimeout];

  if (configuredInterval == nil) {
    return 30;
  }
  return [configuredInterval unsignedIntegerValue];
}

- (NSDictionary *)extraMetricLabels {
  return self.configState[kMetricExtraLabels];
}

- (NSArray<NSString *> *)enabledProcessAnnotations {
  NSArray<NSString *> *annotations = self.configState[kEnabledProcessAnnotations];
  for (id annotation in annotations) {
    if (![annotation isKindOfClass:[NSString class]]) {
      return nil;
    }
  }
  return annotations;
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
  if (!self.syncStateAccessAuthorizerBlock()) {
    return nil;
  }

  NSMutableDictionary *syncState =
    [NSMutableDictionary dictionaryWithContentsOfFile:self.syncStateFilePath];
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
///  Migrate any deprecated sync state keys/values to alternative keys/values.
///
///  Returns YES if any keys were migrated. Otherwise NO.
///
- (BOOL)migrateDeprecatedSyncStateKeys {
  // Currently only one key to migrate
  if (!self.syncState[kSyncCleanRequiredDeprecated]) {
    return NO;
  }

  NSMutableDictionary *syncState = self.syncState.mutableCopy;

  // If the kSyncTypeRequired key exists, its current value will take precedence.
  // Otherwise, migrate the old value to be compatible with the new logic.
  if (!self.syncState[kSyncTypeRequired]) {
    syncState[kSyncTypeRequired] = [self.syncState[kSyncCleanRequiredDeprecated] boolValue]
                                     ? @(SNTSyncTypeClean)
                                     : @(SNTSyncTypeNormal);
  }

  // Delete the deprecated key
  syncState[kSyncCleanRequiredDeprecated] = nil;

  self.syncState = syncState;

  return YES;
}

///
///  Saves the current effective syncState to disk.
///
- (void)saveSyncStateToDisk {
  if (!self.syncStateAccessAuthorizerBlock()) {
    return;
  }

  // Either remove
  NSMutableDictionary *syncState = self.syncState.mutableCopy;
  syncState[kAllowedPathRegexKey] = [syncState[kAllowedPathRegexKey] pattern];
  syncState[kBlockedPathRegexKey] = [syncState[kBlockedPathRegexKey] pattern];
  [syncState writeToFile:self.syncStateFilePath atomically:YES];
  [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions : @0600}
                                   ofItemAtPath:self.syncStateFilePath
                                          error:NULL];
}

- (void)clearSyncState {
  self.syncState = [NSMutableDictionary dictionary];
}

- (NSArray *)entitlementsPrefixFilter {
  return EnsureArrayOfStrings(self.configState[kEntitlementsPrefixFilterKey]);
}

- (NSArray *)entitlementsTeamIDFilter {
  return EnsureArrayOfStrings(self.configState[kEntitlementsTeamIDFilterKey]);
}

#pragma mark Private Defaults Methods

- (NSRegularExpression *)expressionForPattern:(NSString *)pattern {
  if (!pattern) return nil;
  if (![pattern hasPrefix:@"^"]) pattern = [@"^" stringByAppendingString:pattern];
  return [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:NULL];
}

- (void)applyOverrides:(NSMutableDictionary *)forcedConfig {
  // Overrides should only be applied under debug builds.
#ifdef DEBUG
  if ([[[NSProcessInfo processInfo] processName] isEqualToString:@"xctest"] &&
      ![[[NSProcessInfo processInfo] environment] objectForKey:@"ENABLE_CONFIG_OVERRIDES"]) {
    // By default, config overrides are not applied when running tests to help
    // mitigate potential issues due to unexpected config values. This behavior
    // can be overriden if desired by using the env variable: `ENABLE_CONFIG_OVERRIDES`.
    //
    // E.g.:
    //   bazel test --test_env=ENABLE_CONFIG_OVERRIDES=1 ...other test args...
    return;
  }

  NSDictionary *overrides = [NSDictionary dictionaryWithContentsOfFile:kConfigOverrideFilePath];
  for (NSString *key in overrides) {
    id obj = overrides[key];
    if (![obj isKindOfClass:self.forcedConfigKeyTypes[key]] ||
        ([self.forcedConfigKeyTypes[key] isKindOfClass:[NSRegularExpression class]] &&
         ![obj isKindOfClass:[NSString class]])) {
      continue;
    }

    forcedConfig[key] = obj;

    if (self.forcedConfigKeyTypes[key] == [NSRegularExpression class]) {
      NSString *pattern = [obj isKindOfClass:[NSString class]] ? obj : nil;
      forcedConfig[key] = [self expressionForPattern:pattern];
    }
  }
#endif
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

  [self applyOverrides:forcedConfig];

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
#ifdef DEBUG
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
    [self watchOverridesFile];
  });
#endif
}

#ifdef DEBUG
- (void)watchOverridesFile {
  while (![[NSFileManager defaultManager] fileExistsAtPath:kConfigOverrideFilePath]) {
    [NSThread sleepForTimeInterval:0.2];
  }
  [self defaultsChanged:nil];

  int descriptor = open([kConfigOverrideFilePath fileSystemRepresentation], O_EVTONLY);
  if (descriptor < 0) {
    return;
  }

  dispatch_source_t source =
    dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, descriptor,
                           DISPATCH_VNODE_WRITE | DISPATCH_VNODE_RENAME | DISPATCH_VNODE_DELETE,
                           dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
  dispatch_source_set_event_handler(source, ^{
    dispatch_async(dispatch_get_main_queue(), ^{
      [self defaultsChanged:nil];
    });
    unsigned long events = dispatch_source_get_data(source);
    if ((events & DISPATCH_VNODE_DELETE) || (events & DISPATCH_VNODE_RENAME)) {
      dispatch_source_cancel(source);
    }
  });
  dispatch_source_set_cancel_handler(source, ^{
    close(descriptor);
    [self watchOverridesFile];
  });
  dispatch_resume(source);
}
#endif

- (void)defaultsChanged:(void *)v {
  SEL handleChange = @selector(handleChange);
  [NSObject cancelPreviousPerformRequestsWithTarget:self selector:handleChange object:nil];
  [self performSelector:handleChange withObject:nil afterDelay:1.0f];
}

///
///  Update the configState. Triggers a KVO event for all dependents.
///
- (void)handleChange {
  self.configState = [self readForcedConfig];
  [self cacheStaticRules];
}

///
///  Processes the StaticRules key to create SNTRule objects and caches them for quick use
///
- (void)cacheStaticRules {
  NSArray *staticRules = self.configState[kStaticRules];
  if (![staticRules isKindOfClass:[NSArray class]]) return;

  NSMutableDictionary<NSString *, SNTRule *> *rules =
    [NSMutableDictionary dictionaryWithCapacity:staticRules.count];
  for (id rule in staticRules) {
    if (![rule isKindOfClass:[NSDictionary class]]) return;
    SNTRule *r = [[SNTRule alloc] initWithDictionary:rule];
    if (!r) continue;
    rules[r.identifier] = r;
  }
  self.cachedStaticRules = [rules copy];
}

@end
