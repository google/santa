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

#import "SNTStoredEvent.h"

@implementation SNTStoredEvent

+ (BOOL)supportsSecureCoding {  return YES; }

- (void)encodeWithCoder:(NSCoder *)coder {
  [coder encodeObject:self.idx forKey:@"idx"];
  [coder encodeObject:self.fileSHA1 forKey:@"fileSHA1"];
  [coder encodeObject:self.filePath forKey:@"filePath"];

  if (self.fileBundleName) [coder encodeObject:self.fileBundleName forKey:@"fileBundleName"];
  if (self.fileBundleID) [coder encodeObject:self.fileBundleID forKey:@"fileBundleID"];
  if (self.fileBundleVersion) {
    [coder encodeObject:self.fileBundleVersion forKey:@"fileBundleVersion"];
  }
  if (self.fileBundleVersionString) {
    [coder encodeObject:self.fileBundleVersionString forKey:@"fileBundleVersionString"];
  }

  if (self.certSHA1) [coder encodeObject:self.certSHA1 forKey:@"certSHA1"];
  if (self.certCN) [coder encodeObject:self.certCN forKey:@"certCN"];
  if (self.certOrg) [coder encodeObject:self.certOrg forKey:@"certOrg"];
  if (self.certOU) [coder encodeObject:self.certOU forKey:@"certOU"];
  if (self.certValidFromDate) {
    [coder encodeObject:self.certValidFromDate forKey:@"certValidFromDate"];
  }
  if (self.certValidUntilDate) {
    [coder encodeObject:self.certValidUntilDate forKey:@"certValidUntilDate"];
  }

  [coder encodeObject:self.executingUser forKey:@"executingUser"];
  [coder encodeObject:self.occurrenceDate forKey:@"occurrenceDate"];
  [coder encodeInt:self.decision forKey:@"decision"];

  if (self.loggedInUsers) [coder encodeObject:self.loggedInUsers forKey:@"loggedInUsers"];
  if (self.currentSessions) [coder encodeObject:self.currentSessions forKey:@"currentSessions"];
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  _idx = [decoder decodeObjectOfClass:[NSNumber class] forKey:@"idx"];
  _fileSHA1 = [decoder decodeObjectOfClass:[NSString class] forKey:@"fileSHA1"];
  _filePath = [decoder decodeObjectOfClass:[NSString class] forKey:@"filePath"];
  _fileBundleName = [decoder decodeObjectOfClass:[NSString class] forKey:@"fileBundleName"];

  _fileBundleID = [decoder decodeObjectOfClass:[NSString class] forKey:@"fileBundleID"];
  _fileBundleVersion = [decoder decodeObjectOfClass:[NSString class] forKey:@"fileBundleVersion"];
  _fileBundleVersionString =
      [decoder decodeObjectOfClass:[NSString class] forKey:@"fileBundleVersionString"];
  _certSHA1 = [decoder decodeObjectOfClass:[NSString class] forKey:@"certSHA1"];
  _certCN = [decoder decodeObjectOfClass:[NSString class] forKey:@"certCN"];
  _certOrg = [decoder decodeObjectOfClass:[NSString class] forKey:@"certOrg"];
  _certOU = [decoder decodeObjectOfClass:[NSString class] forKey:@"certOU"];
  _certValidFromDate = [decoder decodeObjectOfClass:[NSDate class] forKey:@"certValidFromDate"];
  _certValidUntilDate = [decoder decodeObjectOfClass:[NSDate class] forKey:@"certValidUntilDate"];
  _executingUser = [decoder decodeObjectOfClass:[NSString class] forKey:@"executingUser"];
  _occurrenceDate = [decoder decodeObjectOfClass:[NSDate class] forKey:@"occurrenceDate"];
  _decision = [decoder decodeIntForKey:@"decision"];

  NSSet *stringAndArrayClasses = [NSSet setWithObjects:[NSArray class], [NSString class], nil];
  _loggedInUsers = [decoder decodeObjectOfClasses:stringAndArrayClasses forKey:@"loggedInUsers"];
  _currentSessions = [decoder decodeObjectOfClasses:stringAndArrayClasses
                                             forKey:@"currentSessions"];

  return self;
}

- (BOOL)isEqual:(SNTStoredEvent *)other {
  if (other == self) return YES;
  if (![other isKindOfClass:[SNTStoredEvent class]]) return NO;
  return ([self.fileSHA1 isEqual:other.fileSHA1] &&
          [self.idx isEqual:other.idx]);
}

- (NSUInteger)hash {
  NSUInteger prime = 31;
  NSUInteger result = 1;
  result = prime * result + [self.idx hash];
  result = prime * result + [self.fileSHA1 hash];
  result = prime * result + [self.filePath hash];
  return result;
}

- (NSString *)description {
  return [NSString stringWithFormat:@"SNTStoredEvent[%@] with SHA-1: %@", self.idx, self.fileSHA1];
}

@end
