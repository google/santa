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

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  if (size > 16) {
    std::cerr << "Invalid buffer size of " << size
              <<  " (should be <= 16)" << std::endl;

    return 1;
  }

  santa_vnode_id_t vnodeID = {};
  std::memcpy(&vnodeID, data, size);
  
  MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
  daemonConn.invalidationHandler = ^{
    printf("An error occurred communicating with the daemon, is it running?\n");
    exit(1);
  };

  [daemonConn resume];

  [[daemonConn remoteObjectProxy] checkCacheForVnodeID:vnodeID
                                                  withReply:^(santa_action_t action) {
    if (action == ACTION_RESPOND_ALLOW) {
      std::cerr << "File exists in [whitelist] kernel cache" << std::endl;;
    } else if (action == ACTION_RESPOND_DENY) {
      std::cerr << "File exists in [blacklist] kernel cache" << std::endl;;
    } else if (action == ACTION_UNSET) {
      std::cerr << "File does not exist in cache" << std::endl;;
    }
  }];
  
  return 0;
}
