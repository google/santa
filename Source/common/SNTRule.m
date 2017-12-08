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

#import "SNTRule.h"

@implementation SNTRule

- (instancetype)initWithShasum:(NSString *)shasum
                         state:(SNTRuleState)state
                          type:(SNTRuleType)type
                     customMsg:(NSString *)customMsg {
  self = [super init];
  if (self) {
    _shasum = shasum;
    _state = state;
    _type = type;
    _customMsg = customMsg;
    // TODO: should every rule get a timestamp?
    if (_state == SNTRuleStateWhitelistTransitive) {
      _timestamp = (NSUInteger)[[NSDate date] timeIntervalSinceReferenceDate];
    }
  }
  return self;
}

#pragma mark NSSecureCoding

#define ENCODE(obj, key) if (obj) [coder encodeObject:obj forKey:key]
#define DECODE(cls, key) [decoder decodeObjectOfClass:[cls class] forKey:key]

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(self.shasum, @"shasum");
  ENCODE(@(self.state), @"state");
  ENCODE(@(self.type), @"type");
  ENCODE(self.customMsg, @"custommsg");
  ENCODE(@(self.timestamp), @"timestamp");
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    _shasum = DECODE(NSString, @"shasum");
    _state = [DECODE(NSNumber, @"state") intValue];
    _type = [DECODE(NSNumber, @"type") intValue];
    _customMsg = DECODE(NSString, @"custommsg");
    _timestamp = [DECODE(NSNumber, @"timestamp") unsignedIntegerValue];
  }
  return self;
}

#undef DECODE
#undef ENCODE

- (BOOL)isEqual:(id)other {
  if (other == self) return YES;
  if (![other isKindOfClass:[SNTRule class]]) return NO;
  SNTRule *o = other;
  return ([self.shasum isEqual:o.shasum] &&
          self.state == o.state &&
          self.type == o.type &&
          self.timestamp == o.timestamp);
}

- (NSUInteger)hash {
  NSUInteger prime = 31;
  NSUInteger result = 1;
  result = prime * result + [self.shasum hash];
  result = prime * result + self.state;
  result = prime * result + self.type;
  result = prime * result + self.timestamp;
  return result;
}

- (NSString *)description {
  return [NSString stringWithFormat:@"SNTRule: SHA-256: %@, State: %ld, Type: %ld, Timestamp: %lu",
          self.shasum, self.state, self.type, (unsigned long)self.timestamp];
}

@end
