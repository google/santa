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

#import <Foundation/Foundation.h>

///
///  Store information about new allowlist rules for later logging.
///
@interface SNTAllowlistInfo : NSObject

@property pid_t pid;
@property int pidversion;
@property NSString *targetPath;
@property NSString *sha256;

- (instancetype)initWithPid:(pid_t)pid
                 pidversion:(int)pidver
                 targetPath:(NSString*)targetPath
                     sha256:(NSString*)hash;

@end
