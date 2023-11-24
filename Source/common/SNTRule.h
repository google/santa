/// Copyright 2015-2022 Google Inc. All rights reserved.
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
///  Represents a Rule.
///
@interface SNTRule : NSObject <NSSecureCoding>

///
///  The hash of the object this rule is for
///
@property(copy) NSString *identifier;

///
///  The state of this rule
///
@property SNTRuleState state;

///
///  The type of object this rule is for (binary, certificate)
///
@property SNTRuleType type;

///
///  A custom message that will be displayed if this rule blocks a binary from executing
///
@property(copy) NSString *customMsg;

///
///  A custom URL to take the user to when this binary is blocked from executing.
///
@property(copy) NSString *customURL;

///
///  The time when this rule was last retrieved from the rules database, if rule is transitive.
///  Stored as number of seconds since 00:00:00 UTC on 1 January 2001.
///
@property(readonly) NSUInteger timestamp;

///
///  Designated initializer.
///
- (instancetype)initWithIdentifier:(NSString *)identifier
                             state:(SNTRuleState)state
                              type:(SNTRuleType)type
                         customMsg:(NSString *)customMsg
                         timestamp:(NSUInteger)timestamp;

///
///  Initialize with a default timestamp: current time if rule state is transitive, 0 otherwise.
///
- (instancetype)initWithIdentifier:(NSString *)identifier
                             state:(SNTRuleState)state
                              type:(SNTRuleType)type
                         customMsg:(NSString *)customMsg;

///
///  Initialize with a dictionary received from a sync server.
///
- (instancetype)initWithDictionary:(NSDictionary *)dict;

///
///  Sets timestamp of rule to the current time.
///
- (void)resetTimestamp;

///
///  Returns a dictionary representation of the rule.
///
- (NSDictionary *)dictionaryRepresentation;

///
///  Returns a SHA-256 digest of this rule.
///  The format of this digest must be consistent to allow possible reimplementation outside of
///  Santa The digest is a SHA-256 of the rule values separated by colons in the following order:
///
///    identifier:state:type:timestamp
///
///  The state and type are long integers. The timestamp is a long unsigned integer.
///
///  The custom URL and custom message fields are not part of the hash because:
///    a) They could potentially be very long and slow down hashing
///    b) They could be formatted in a very slightly different way causing hash values not to match
///    c) They are not part of the evaluation for a rule and so are not critical like the other
///    values are
///
- (NSString *)digest;

@end
