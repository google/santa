/// Copyright 2018 Google Inc. All rights reserved.
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

#import "SNTKernelCommon.h"

@class SNTCachedDecision;
@class SNTStoredEvent;

///
///  Logs execution and file write events to syslog
///
@interface SNTEventLog : NSObject
// Methods implemented by a concrete subclass.
- (void)logDiskAppeared:(NSDictionary *)diskProperties;
- (void)logDiskDisappeared:(NSDictionary *)diskProperties;
- (void)logFileModification:(santa_message_t)message;
- (void)logDeniedExecution:(SNTCachedDecision *)cd withMessage:(santa_message_t)message;
- (void)logAllowedExecution:(santa_message_t)message;
- (void)logBundleHashingEvents:(NSArray<SNTStoredEvent *> *)events;

// Getter and setter for cached decisions.
- (SNTCachedDecision *)cachedDecisionForMessage:(santa_message_t)message;
- (void)cacheDecision:(SNTCachedDecision *)cd;

// String formatter helpers.
- (void)addArgsForPid:(pid_t)pid toString:(NSMutableString *)str;
- (NSString *)diskImageForDevice:(NSString *)devPath;
- (NSString *)nameForUID:(uid_t)uid;
- (NSString *)nameForGID:(gid_t)gid;
- (NSString *)sanitizeString:(NSString *)inStr;
- (NSString *)serialForDevice:(NSString *)devPath;
- (NSString *)originalPathForTranslocation:(santa_message_t)message;

// A cache for usernames and groups.
@property(readonly, nonatomic) NSCache<NSNumber *, NSString *> *userNameMap;
@property(readonly, nonatomic) NSCache<NSNumber *, NSString *> *groupNameMap;

// A UTC Date formatter.
@property(readonly, nonatomic) NSDateFormatter *dateFormatter;
@end
