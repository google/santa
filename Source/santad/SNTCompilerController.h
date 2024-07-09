/// Copyright 2017-2022 Google Inc. All rights reserved.
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
#include <bsm/libbsm.h>

#include <memory>

#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"

@interface SNTCompilerController : NSObject

// This function will determine if the instigating process was a compiler and,
// for appropriate events, will create appropriate transitive rules.
- (BOOL)handleEvent:(const santa::Message &)msg withLogger:(std::shared_ptr<santa::Logger>)logger;

// Set whether or not the given audit token should be tracked as a compiler
- (void)setProcess:(const audit_token_t &)tok isCompiler:(bool)isCompiler;

@end
