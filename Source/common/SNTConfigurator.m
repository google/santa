/// Copyright 2014 Google Inc. All rights reserved.
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

@interface SNTConfigurator ()
@property NSMutableDictionary *configData;
@end

@implementation SNTConfigurator

/// The hard-coded path to the config file
static NSString * const kConfigFilePath = @"/var/db/santa/config.plist";

/// The keys in the config file
static NSString * const kSyncBaseURLKey = @"SyncBaseURL";
static NSString * const kClientAuthCertificateFileKey = @"ClientAuthCertificateFile";
static NSString * const kClientAuthCertificatePasswordKey = @"ClientAuthCertificatePassword";
static NSString * const kClientAuthCertificateCNKey = @"ClientAuthCertificateCN";
static NSString * const kClientAuthCertificateIssuerKey = @"ClientAuthCertificateIssuerCN";
static NSString * const kServerAuthRootsDataKey = @"ServerAuthRootsData";
static NSString * const kServerAuthRootsFileKey = @"ServerAuthRootsFile";
static NSString * const kDebugLoggingKey = @"DebugLogging";
static NSString * const kClientModeKey = @"ClientMode";

static NSString * const kMachineOwnerKey = @"MachineOwner";
static NSString * const kMachineIDKey = @"MachineID";

static NSString * const kMachineOwnerPlistFileKey = @"MachineOwnerPlist";
static NSString * const kMachineOwnerPlistKeyKey = @"MachineOwnerKey";

static NSString * const kMachineIDPlistFileKey = @"MachineIDPlist";
static NSString * const kMachineIDPlistKeyKey = @"MachineIDKey";

- (instancetype)init {
  self = [super init];
  if (self) {
    [self reloadConfigData];
  }
  return self;
}

# pragma mark Singleton retriever

+ (instancetype)configurator {
  static SNTConfigurator *sharedConfigurator = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedConfigurator = [[SNTConfigurator alloc] init];
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
    return plist[kMachineOwnerPlistKeyKey];
  }

  if (self.configData[kMachineOwnerKey]) {
    return self.configData[kMachineOwnerKey];
  }

  return @"";
}

- (NSString *)machineIDOverride {
  if (self.configData[kMachineIDPlistFileKey] && self.configData[kMachineIDPlistKeyKey]) {
    NSDictionary *plist =
        [NSDictionary dictionaryWithContentsOfFile:self.configData[kMachineIDPlistFileKey]];
    return plist[kMachineIDPlistKeyKey];
  }

  if (self.configData[kMachineIDKey]) {
    return self.configData[kMachineIDKey];
  }

  return @"";
}

- (BOOL)debugLogging {
  return [self.configData[kDebugLoggingKey] boolValue];
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

#pragma mark Private

- (void)saveConfigToDisk {
  [self.configData writeToFile:kConfigFilePath atomically:YES];
}

- (void)reloadConfigData {
  NSError* error = nil;

  NSData *readData = [NSData dataWithContentsOfFile:kConfigFilePath options:0 error:&error];

  if (error) {
    fprintf(stderr, "%s\n", [[NSString stringWithFormat:@"Could not open configuration file %@: %@", kConfigFilePath, [error localizedDescription]] UTF8String]);

    exit(1);
  }

  CFErrorRef parseError = NULL;

  NSDictionary *dictionary = (__bridge_transfer NSDictionary *)CFPropertyListCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)readData, kCFPropertyListImmutable, NULL, (CFErrorRef *)&parseError);

  if (parseError) {
    fprintf(stderr, "%s\n", [[NSString stringWithFormat:@"Could not parse configuration file %@: %@", kConfigFilePath, [(__bridge NSError *)parseError localizedDescription]] UTF8String]);

    exit(1);
  }

  _configData = [dictionary mutableCopy];
}

@end
