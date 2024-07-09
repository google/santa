/// Copyright 2022 Google Inc. All rights reserved.
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

#include <string>
#include <vector>

#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Metrics.h"

// Protocol that all subclasses of `SNTEndpointSecurityClient` should adhere to.
@protocol SNTEndpointSecurityEventHandler <NSObject>

// Called Synchronously and serially for each message provided by the
// EndpointSecurity framework.
- (void)handleMessage:(santa::Message &&)esMsg
   recordEventMetrics:(void (^)(santa::EventDisposition))recordEventMetrics;

// Called after Santa has finished initializing itself.
// This is an optimal place to subscribe to ES events
- (void)enable;

@end

// Extension of the `SNTEndpointSecurityEventHandler` protocol for
// `SNTEndpointSecurityClient` subclasses that can be dynamically
// enabled and disabled.
@protocol SNTEndpointSecurityDynamicEventHandler <SNTEndpointSecurityEventHandler>

// Called when a client should no longer receive events.
- (void)disable;

- (void)watchItemsCount:(size_t)count
               newPaths:
                 (const std::vector<std::pair<std::string, santa::WatchItemPathType>> &)newPaths
           removedPaths:
             (const std::vector<std::pair<std::string, santa::WatchItemPathType>> &)removedPaths;

@end
