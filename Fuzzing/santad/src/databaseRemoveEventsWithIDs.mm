/// Copyright 2018 Google Inc. All rights reserved.
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

#include <iostream>
#include <cstdint>

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "SNTCommandController.h"
#import "SNTRule.h"
#import "SNTXPCControlInterface.h"

#pragma pack(push, 1)

#pragma pack(pop)

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  auto *eventId = reinterpret_cast<const std::uint64_t *>(data);
  std::size_t eventIdCount = size / sizeof(std::uint64_t);
  if (eventIdCount == 0) {
    return 0;
  }

  MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
  daemonConn.invalidationHandler = ^{
    printf("An error occurred communicating with the daemon, is it running?\n");
    exit(1);
  };

  [daemonConn resume];

  NSMutableSet *eventIds = [NSMutableSet setWithCapacity:eventIdCount];
  for (std::size_t i = 0; i < eventIdCount; i++) {
    auto id = [NSNumber numberWithInteger:eventId[i]];
    [eventIds addObject:id];
  }

  [[daemonConn remoteObjectProxy] databaseRemoveEventsWithIDs:[eventIds allObjects]];
  return 0;
}
