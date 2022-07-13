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

#import "Source/common/SNTRule.h"
#import "Source/common/SNTSyncConstants.h"

@interface SNTRule ()
@property(readwrite) NSUInteger timestamp;
@end

@implementation SNTRule

- (instancetype)initWithIdentifier:(NSString *)identifier
                             state:(SNTRuleState)state
                              type:(SNTRuleType)type
                         customMsg:(NSString *)customMsg
                         timestamp:(NSUInteger)timestamp {
  self = [super init];
  if (self) {
    _identifier = identifier;
    _state = state;
    _type = type;
    _customMsg = customMsg;
    _timestamp = timestamp;
  }
  return self;
}

- (instancetype)initWithIdentifier:(NSString *)identifier
                             state:(SNTRuleState)state
                              type:(SNTRuleType)type
                         customMsg:(NSString *)customMsg {
  self = [self initWithIdentifier:identifier state:state type:type customMsg:customMsg timestamp:0];
  // Initialize timestamp to current time if rule is transitive.
  if (self && state == SNTRuleStateAllowTransitive) {
    [self resetTimestamp];
  }
  return self;
}

// Converts rule information downloaded from the server into a SNTRule.  Because any information
// not recorded by SNTRule is thrown away here, this method is also responsible for dealing with
// the extra bundle rule information (bundle_hash & rule_count).
- (instancetype)initWithDictionary:(NSDictionary *)dict {
  if (![dict isKindOfClass:[NSDictionary class]]) return nil;

  self = [super init];
  if (self) {
    _identifier = dict[kRuleIdentifier];
    if (!_identifier.length) _identifier = dict[kRuleSHA256];
    if (!_identifier.length) {
      return nil;
    }

    NSString *policyString = dict[kRulePolicy];
    if ([policyString isEqual:kRulePolicyAllowlist] ||
        [policyString isEqual:kRulePolicyAllowlistDeprecated]) {
      _state = SNTRuleStateAllow;
    } else if ([policyString isEqual:kRulePolicyAllowlistCompiler] ||
               [policyString isEqual:kRulePolicyAllowlistCompilerDeprecated]) {
      _state = SNTRuleStateAllowCompiler;
    } else if ([policyString isEqual:kRulePolicyBlocklist] ||
               [policyString isEqual:kRulePolicyBlocklistDeprecated]) {
      _state = SNTRuleStateBlock;
    } else if ([policyString isEqual:kRulePolicySilentBlocklist] ||
               [policyString isEqual:kRulePolicySilentBlocklistDeprecated]) {
      _state = SNTRuleStateSilentBlock;
    } else if ([policyString isEqual:kRulePolicyRemove]) {
      _state = SNTRuleStateRemove;
    } else {
      return nil;
    }

    NSString *ruleTypeString = dict[kRuleType];
    if ([ruleTypeString isEqual:kRuleTypeBinary]) {
      _type = SNTRuleTypeBinary;
    } else if ([ruleTypeString isEqual:kRuleTypeCertificate]) {
      _type = SNTRuleTypeCertificate;
    } else if ([ruleTypeString isEqual:kRuleTypeTeamID]) {
      _type = SNTRuleTypeTeamID;
    } else {
      return nil;
    }

    NSString *customMsg = dict[kRuleCustomMsg];
    if (customMsg.length) {
      _customMsg = customMsg;
    }
  }
  return self;
}

#pragma mark NSSecureCoding

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-literal-conversion"
#define ENCODE(obj, key) \
  if (obj) [coder encodeObject:obj forKey:key]
#define DECODE(cls, key) [decoder decodeObjectOfClass:[cls class] forKey:key]

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(self.identifier, @"identifier");
  ENCODE(@(self.state), @"state");
  ENCODE(@(self.type), @"type");
  ENCODE(self.customMsg, @"custommsg");
  ENCODE(@(self.timestamp), @"timestamp");
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    _identifier = DECODE(NSString, @"identifier");
    _state = [DECODE(NSNumber, @"state") intValue];
    _type = [DECODE(NSNumber, @"type") intValue];
    _customMsg = DECODE(NSString, @"custommsg");
    _timestamp = [DECODE(NSNumber, @"timestamp") unsignedIntegerValue];
  }
  return self;
}

#undef DECODE
#undef ENCODE
#pragma clang diagnostic pop

- (BOOL)isEqual:(id)other {
  if (other == self) return YES;
  if (![other isKindOfClass:[SNTRule class]]) return NO;
  SNTRule *o = other;
  return ([self.identifier isEqual:o.identifier] && self.state == o.state && self.type == o.type);
}

- (NSUInteger)hash {
  NSUInteger prime = 31;
  NSUInteger result = 1;
  result = prime * result + [self.identifier hash];
  result = prime * result + self.state;
  result = prime * result + self.type;
  return result;
}

- (NSString *)description {
  return [NSString
    stringWithFormat:@"SNTRule: Identifier: %@, State: %ld, Type: %ld, Timestamp: %lu",
                     self.identifier, self.state, self.type, (unsigned long)self.timestamp];
}

#pragma mark Last-access Timestamp

- (void)resetTimestamp {
  self.timestamp = (NSUInteger)[[NSDate date] timeIntervalSinceReferenceDate];
}

@end
