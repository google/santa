/// Copyright 2021 Google Inc. All rights reserved.
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

#import "Source/common/SNTAllowlistInfo.h"

@implementation SNTAllowlistInfo

- (instancetype)initWithPid:(pid_t)pid
                 pidversion:(int)pidver
                 targetPath:(NSString*)targetPath
                     sha256:(NSString*)hash {
  self = [super init];
  if (self) {
    _pid = pid;
    _pidversion = pidver;
    _targetPath = targetPath;
    _sha256 = hash;
  }
  return self;
}
@end
