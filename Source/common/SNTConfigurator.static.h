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

#import <Foundation/Foundation.h>

#import "Source/common/SNTCommonEnums.h"

///
///  Singleton that provides an interface for managing configuration values on disk
///  @note This class is designed as a singleton but that is not strictly enforced.
///  @note All properties are KVO compliant.
///
@interface SNTConfigurator : NSObject

/// Holds the configurations from a sync server and mobileconfig.
@property(atomic) NSDictionary *syncState;
@property(atomic) NSMutableDictionary *configState;

@property(readonly, nonatomic) NSDictionary *syncServerKeyTypes;
@property(readonly, nonatomic) NSDictionary *forcedConfigKeyTypes;

/// Holds the last processed hash of the static rules list.
@property(atomic) NSDictionary *cachedStaticRules;

/// Was --debug passed as an argument to this process?
@property(readonly, nonatomic) BOOL debugFlag;

/// Holds the SyncBaseURL property. Declared here to allow sync state save/restore methods
/// to avoid doing work unnecessarily.
@property(readonly, nonatomic) NSURL *syncBaseURL;

+ (NSSet *)configStateSet;
+ (NSSet *)syncStateSet;
+ (NSSet *)syncAndConfigStateSet;

- (void)updateSyncStateForKey:(NSString *)key value:(id)value;

///
///  Retrieve an initialized singleton configurator object using the default file path.
///
+ (instancetype)configurator;

///
///  Clear the sync server configuration from the effective configuration.
///
- (void)clearSyncState;

@end
