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

#import "SNTCommonEnums.h"
#import "SNTDatabaseTable.h"

@class SNTRule;
@class SNTNotificationMessage;

///
///  Responsible for managing the rule tables.
///
@interface SNTRuleTable : SNTDatabaseTable

///
///  @return Number of rules in the database
///
- (NSUInteger)ruleCount;

///
///  @return Number of binary rules in the database
///
- (NSUInteger)binaryRuleCount;

///
///  @return Number of certificate rules in the database
///
- (NSUInteger)certificateRuleCount;

///
///  @return Rule for binary with given SHA-256
///
- (SNTRule *)binaryRuleForSHA256:(NSString *)SHA256;

///
///  @return Rule for certificate with  given SHA-256
///
- (SNTRule *)certificateRuleForSHA256:(NSString *)SHA256;

///
///  Add an array of rules to the database. The rules will be added within a transaction and the
///  transaction will abort if any rule fails to add.
///
///  @param rules Array of SNTRule's to add.
///  @param cleanSlate If true, remove all rules before adding the new rules.
///  @param error When returning NO, will be filled with appropriate error.
///  @return YES if adding all rules passed, NO if any were rejected.
///
- (BOOL)addRules:(NSArray *)rules cleanSlate:(BOOL)cleanSlate error:(NSError **)error;

@end
