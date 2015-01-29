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

#import "SNTNotificationMessage.h"

#import "SNTCertificate.h"

@implementation SNTNotificationMessage

static NSString *const kPathKey = @"path";
static NSString *const kSHA256Key = @"sha256";
static NSString *const kCertificatesKey = @"certificates";
static NSString *const kCustomMessageKey = @"custommessage";

#pragma mark NSSecureCoding

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeObject:self.path forKey:kPathKey];
  [coder encodeObject:self.SHA256 forKey:kSHA256Key];
  [coder encodeObject:self.customMessage forKey:kCustomMessageKey];
  [coder encodeObject:self.certificates forKey:kCertificatesKey];
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  _path = [decoder decodeObjectOfClass:[NSString class] forKey:kPathKey];
  _SHA256 = [decoder decodeObjectOfClass:[NSString class] forKey:kSHA256Key];
  _customMessage = [decoder decodeObjectOfClass:[NSString class] forKey:kCustomMessageKey];

  NSSet *certClasses = [NSSet setWithObjects:[NSArray class], [SNTCertificate class], nil];
  _certificates = [decoder decodeObjectOfClasses:certClasses forKey:kCertificatesKey];
  return self;
}

#pragma mark Calculated Properties

- (SNTCertificate *)leafCertificate {
  return [self.certificates firstObject];
}

@end
