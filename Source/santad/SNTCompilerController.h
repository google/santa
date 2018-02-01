/// Copyright 2017 Google Inc. All rights reserved.
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
#import "SNTKernelCommon.h"

@class SNTDriverManager;
@class SNTEventLog;

@interface SNTCompilerController : NSObject
// Designated initializer takes a SNTEventLog instance so that we can
// call saveDecisionDetails: to create a fake cached decision for transitive
// rule creation requests that are still pending.
- (instancetype)initWithDriverManager:(SNTDriverManager *)driverManager
                             eventLog:(SNTEventLog *)eventLog;

// Whenever an executable file is closed or renamed whitelist the resulting file.
// We assume that we have already determined that the writing process was a compiler.
- (void)createTransitiveRule:(santa_message_t)message;
@end
