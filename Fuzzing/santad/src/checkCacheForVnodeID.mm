#include <iostream>
#include <cstdint>

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "SNTCommandController.h"
#import "SNTRule.h"
#import "SNTXPCControlInterface.h"

#pragma pack(push, 1)

#pragma pack(pop)

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
