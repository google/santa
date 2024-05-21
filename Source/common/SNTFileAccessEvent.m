/// Copyright 2023 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import "Source/common/SNTFileAccessEvent.h"

#import "Source/common/CertificateHelpers.h"

@implementation SNTFileAccessEvent

#define ENCODE(o)                               \
  do {                                          \
    if (self.o) {                               \
      [coder encodeObject:self.o forKey:@(#o)]; \
    }                                           \
  } while (0)

#define DECODE(o, c)                                             \
  do {                                                           \
    _##o = [decoder decodeObjectOfClass:[c class] forKey:@(#o)]; \
  } while (0)

#define DECODEARRAY(o, c)                                                                        \
  do {                                                                                           \
    _##o = [decoder decodeObjectOfClasses:[NSSet setWithObjects:[NSArray class], [c class], nil] \
                                   forKey:@(#o)];                                                \
  } while (0)

- (instancetype)init {
  self = [super init];
  if (self) {
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  ENCODE(accessedPath);
  ENCODE(ruleVersion);
  ENCODE(ruleName);
  ENCODE(application);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE(accessedPath, NSString);
    DECODE(ruleVersion, NSString);
    DECODE(ruleName, NSString);
    DECODE(application, NSString);
  }
  return self;
}

- (NSString *)description {
  return [NSString
    stringWithFormat:@"SNTFileAccessEvent: Accessed: %@, By: %@", self.accessedPath, self.filePath];
}

- (NSString *)publisherInfo {
  return Publisher(self.signingChain, self.teamID);
}

- (NSArray *)signingChainCertRefs {
  return CertificateChain(self.signingChain);
}

@end
