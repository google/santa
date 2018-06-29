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
#include <vector>

#include <SNTCommandSyncRuleDownload.h>
#include <SNTCommandSyncState.h>
#include <SNTCommandSyncConstants.h>
#include <SNTRule.h>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  NSData *buffer = [NSData dataWithBytes:static_cast<const void *>(data) length:size];
  if (!buffer) {
    return 0;
  }

  NSError *error;
  NSDictionary *response = [NSJSONSerialization JSONObjectWithData:buffer options:0 error:&error];
  if (!response) {
    return 0;
  }

  if (![response isKindOfClass:[NSDictionary class]]) {
    return 0;
  }

  if (![response objectForKey:kRules]) {
    return 0;
  }

  SNTCommandSyncState *state = [[SNTCommandSyncState alloc] init];
  if (!state) {
    return 0;
  }

  SNTCommandSyncRuleDownload *obj = [[SNTCommandSyncRuleDownload alloc] initWithState:state];
  if (!obj) {
    return 0;
  }

  for (NSDictionary *ruleDict in response[kRules]) {
    SNTRule *rule = [obj ruleFromDictionary:ruleDict];
    if (rule) {
      std::cerr << "Rule: " << [[rule description] UTF8String] << "\n";
    }
  }
 
  return 0;
}
