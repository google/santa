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

#import "SNTStoredEvent.h"

#import "MOLCertificate.h"

@implementation SNTStoredEvent

#define ENCODE(obj, key) if (obj) [coder encodeObject:obj forKey:key]
#define DECODE(cls, key) [decoder decodeObjectOfClass:[cls class] forKey:key]
#define DECODEARRAY(cls, key) \
    [decoder decodeObjectOfClasses:[NSSet setWithObjects:[NSArray class], [cls class], nil] \
                            forKey:key]

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(self.idx, @"idx");
  ENCODE(self.fileSHA256, @"fileSHA256");
  ENCODE(self.filePath, @"filePath");

  ENCODE(self.fileBundleName, @"fileBundleName");
  ENCODE(self.fileBundlePath, @"fileBundlePath");
  ENCODE(self.fileBundleID, @"fileBundleID");
  ENCODE(self.fileBundleVersion, @"fileBundleVersion");
  ENCODE(self.fileBundleVersionString, @"fileBundleVersionString");

  ENCODE(self.signingChain, @"signingChain");

  ENCODE(self.executingUser, @"executingUser");
  ENCODE(self.occurrenceDate, @"occurrenceDate");
  ENCODE(@(self.decision), @"decision");
  ENCODE(self.pid, @"pid");
  ENCODE(self.ppid, @"ppid");
  ENCODE(self.parentName, @"parentName");

  ENCODE(self.loggedInUsers, @"loggedInUsers");
  ENCODE(self.currentSessions, @"currentSessions");

  ENCODE(self.quarantineDataURL, @"quarantineDataURL");
  ENCODE(self.quarantineRefererURL, @"quarantineRefererURL");
  ENCODE(self.quarantineTimestamp, @"quarantineTimestamp");
  ENCODE(self.quarantineAgentBundleID, @"quarantineAgentBundleID");
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    _idx = DECODE(NSNumber, @"idx");
    _fileSHA256 = DECODE(NSString, @"fileSHA256");
    _filePath = DECODE(NSString, @"filePath");

    _fileBundleName = DECODE(NSString, @"fileBundleName");
    _fileBundlePath = DECODE(NSString, @"fileBundlePath");
    _fileBundleID = DECODE(NSString, @"fileBundleID");
    _fileBundleVersion = DECODE(NSString, @"fileBundleVersion");
    _fileBundleVersionString = DECODE(NSString, @"fileBundleVersionString");

    _signingChain = DECODEARRAY(MOLCertificate, @"signingChain");

    _executingUser = DECODE(NSString, @"executingUser");
    _occurrenceDate = DECODE(NSDate, @"occurrenceDate");
    _decision = (SNTEventState)[DECODE(NSNumber, @"decision") intValue];
    _pid = DECODE(NSNumber, @"pid");
    _ppid = DECODE(NSNumber, @"ppid");
    _parentName = DECODE(NSString, @"parentName");

    _loggedInUsers = DECODEARRAY(NSString, @"loggedInUsers");
    _currentSessions = DECODEARRAY(NSString, @"currentSessions");

    _quarantineDataURL = DECODE(NSString, @"quarantineDataURL");
    _quarantineRefererURL = DECODE(NSString, @"quarantineRefererURL");
    _quarantineTimestamp = DECODE(NSDate, @"quarantineTimestamp");
    _quarantineAgentBundleID = DECODE(NSString, @"quarantineAgentBundleID");
  }
  return self;
}

- (BOOL)isEqual:(id)other {
  if (other == self) return YES;
  if (![other isKindOfClass:[SNTStoredEvent class]]) return NO;
  SNTStoredEvent *o = other;
  return ([self.fileSHA256 isEqual:o.fileSHA256] && [self.idx isEqual:o.idx]);
}

- (NSUInteger)hash {
  NSUInteger prime = 31;
  NSUInteger result = 1;
  result = prime * result + [self.idx hash];
  result = prime * result + [self.fileSHA256 hash];
  result = prime * result + [self.occurrenceDate hash];
  return result;
}

- (NSString *)description {
  return
      [NSString stringWithFormat:@"SNTStoredEvent[%@] with SHA-256: %@", self.idx, self.fileSHA256];
}

@end
