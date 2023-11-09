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

#import "Source/common/SNTDeepCopy.h"

@implementation NSArray (SNTDeepCopy)

- (instancetype)sntDeepCopy {
  NSMutableArray<__kindof NSObject *> *deepCopy = [NSMutableArray arrayWithCapacity:self.count];
  for (id object in self) {
    if ([object respondsToSelector:@selector(sntDeepCopy)]) {
      [deepCopy addObject:[object sntDeepCopy]];
    } else if ([object respondsToSelector:@selector(copyWithZone:)]) {
      [deepCopy addObject:[object copy]];
    } else {
      [deepCopy addObject:object];
    }
  }
  return deepCopy;
}

@end

@implementation NSDictionary (SNTDeepCopy)

- (instancetype)sntDeepCopy {
  NSMutableDictionary<__kindof NSObject *, __kindof NSObject *> *deepCopy =
    [NSMutableDictionary dictionary];
  for (id key in self) {
    id value = self[key];
    if ([value respondsToSelector:@selector(sntDeepCopy)]) {
      deepCopy[key] = [value sntDeepCopy];
    } else if ([value respondsToSelector:@selector(copyWithZone:)]) {
      deepCopy[key] = [value copy];
    } else {
      deepCopy[key] = value;
    }
  }
  return deepCopy;
}

@end
