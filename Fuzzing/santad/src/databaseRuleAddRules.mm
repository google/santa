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

struct InputData {
  std::uint32_t cleanSlate;
  std::uint32_t state;
  std::uint32_t type;
  char hash[33];
};

#pragma pack(pop)

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  if (size > sizeof(InputData)) {
    std::cerr << "Invalid buffer size of " << size
              <<  " (should be <= " << sizeof(InputData)
              << ")" << std::endl;

    return 1;
  }

  InputData input_data = {};
  std::memcpy(&input_data, data, size);

  SNTRule *newRule = [[SNTRule alloc] init];
  newRule.state = (SNTRuleState) input_data.state;
  newRule.type = (SNTRuleType) input_data.type;
  newRule.shasum = @(input_data.hash);
  newRule.customMsg = @"";
  
  MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
  daemonConn.invalidationHandler = ^{
    printf("An error occurred communicating with the daemon, is it running?\n");
    exit(1);
  };

  [daemonConn resume];
  [[daemonConn remoteObjectProxy] databaseRuleAddRules:@[newRule]
                                                 cleanSlate:NO
                                                      reply:^(NSError *error) {
    if (!error) {
      if (newRule.state == SNTRuleStateRemove) {
        printf("Removed rule for SHA-256: %s.\n", [newRule.shasum UTF8String]);
      } else {
        printf("Added rule for SHA-256: %s.\n", [newRule.shasum UTF8String]);
      }
    }
  }];
  
  return 0;
}
