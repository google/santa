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

@interface SNTCompilerController : NSObject

// Designated initializer for SNTCompilerController.  It must be passed a SNTDriverManager so that
// it can communicate with the kernel (sending it a processTerminated message).
- (instancetype)initWithDriverManager:(SNTDriverManager *)driverManager;

// Whenever a compiler binary is executed, this starts monitoring its pid so that we can send a
// message back to the kernel when the process terminates, notifying the kernel that it should
// remove the pid from its cache of pids associated with compiler processes.
- (void)monitorCompilerProcess:(pid_t)pid;

// Whenever an executable file is closed or renamed whitelist the resulting file.
// We assume that we have already determined that the writing process was a compiler.
- (void)checkForNewExecutable:(santa_message_t)message;
@end
