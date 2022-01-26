#import "Source/common/SNTDeviceEvent.h"

@implementation SNTDeviceEvent

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-literal-conversion"

#define ENCODE(obj, key) \
  if (obj) [coder encodeObject:obj forKey:key]
#define DECODE(cls, key) [decoder decodeObjectOfClass:[cls class] forKey:key]
#define DECODEARRAY(cls, key)                                                             \
  [decoder decodeObjectOfClasses:[NSSet setWithObjects:[NSArray class], [cls class], nil] \
                          forKey:key]

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(self.mntonname, @"mntonname");
  ENCODE(self.mntfromname, @"mntfromname");
  ENCODE(self.remountArgs, @"remountArgs");
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    _mntonname = DECODE(NSString, @"mntonname");
    _mntfromname = DECODE(NSString, @"mntfromname");
    _remountArgs = DECODEARRAY(NSString, @"remountArgs");
  }
  return self;
}
- (NSString *)description {
  return [NSString stringWithFormat:@"SNTDeviceEvent '%@' -> '%@' (with permissions: [%@]",
                                    self.mntfromname, self.mntonname,
                                    [self.remountArgs componentsJoinedByString:@", "]];
}

@end
