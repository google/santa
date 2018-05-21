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

#import "SNTCommonEnums.h"

///
///  Represents a Rule.
///
@interface SNTRule : NSObject<NSSecureCoding>

///
///  The hash of the object this rule is for
///
@property(copy) NSString *shasum;

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
///  The time when this rule was last retrieved from the rules database, if rule is transitive.
///  Stored as number of seconds since 00:00:00 UTC on 1 January 2001.
///
@property(readonly) NSUInteger timestamp;

///
///  Designated initializer.
///
- (instancetype)initWithShasum:(NSString *)shasum
                         state:(SNTRuleState)state
                          type:(SNTRuleType)type
                     customMsg:(NSString *)customMsg
                     timestamp:(NSUInteger)timestamp;

///
///  Initialize with a default timestamp: current time if rule state is transitive, 0 otherwise.
///
- (instancetype)initWithShasum:(NSString *)shasum
                         state:(SNTRuleState)state
                          type:(SNTRuleType)type
                     customMsg:(NSString *)customMsg;

///
///  Sets timestamp of rule to the current time.
///
- (void)resetTimestamp;

@end
