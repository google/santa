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

#include "SNTCommonEnums.h"

///
///  Represents an event stored in the database.
///
@interface SNTStoredEvent : NSObject<NSSecureCoding>

@property NSNumber *idx;
@property NSString *fileSHA256;
@property NSString *filePath;
@property NSString *fileBundleName;
@property NSString *fileBundleID;
@property NSString *fileBundleVersion;
@property NSString *fileBundleVersionString;
@property NSString *certSHA1;
@property NSString *certCN;
@property NSString *certOrg;
@property NSString *certOU;
@property NSDate *certValidFromDate;
@property NSDate *certValidUntilDate;
@property NSString *executingUser;
@property NSDate *occurrenceDate;
@property santa_eventstate_t decision;
@property NSArray *loggedInUsers;
@property NSArray *currentSessions;
@property NSNumber *pid;

@end
