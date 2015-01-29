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

#import "SNTDatabaseTable.h"

#include "SNTCommonEnums.h"

@class SNTRule;
@class SNTNotificationMessage;

///
///  Responsible for managing the cache tables in the Santa database (certificates & binaries)
///
@interface SNTRuleTable : SNTDatabaseTable

///
///  @return Number of rules in the database
///
- (long)ruleCount;

///
///  @return Number of binary rules in the database
///
- (long)binaryRuleCount;

///
///  @return Number of certificate rules in the database
///
- (long)certificateRuleCount;

///
///  @return Rule for binary with given SHA-256
///
- (SNTRule *)binaryRuleForSHA256:(NSString *)SHA256;

///
///  @return Rule for certificate with given SHA-1
///
- (SNTRule *)certificateRuleForSHA1:(NSString *)SHA1;

///
///  Add a single rule to the database
///
- (void)addRule:(SNTRule *)rule;

///
///  Add an array of rules to the database
///
- (void)addRules:(NSArray *)rules;

@end
