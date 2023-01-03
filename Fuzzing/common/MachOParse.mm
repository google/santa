#import <Foundation/Foundation.h>
#include <libproc.h>
#include <stddef.h>
#include <stdint.h>

#import "Source/common/SNTFileInfo.h"

int get_num_fds() {
  return proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0) / PROC_PIDLISTFD_SIZE;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static NSString *tmpPath =
    [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];

  int num_fds_pre = get_num_fds();

  @autoreleasepool {
    NSData *input = [NSData dataWithBytesNoCopy:(void *)data length:size freeWhenDone:false];
    [input writeToFile:tmpPath atomically:false];

    NSError *error;
    SNTFileInfo *fi = [[SNTFileInfo alloc] initWithResolvedPath:tmpPath error:&error];
    if (!fi || error != nil) {
      NSLog(@"Error: %@", error);
      return -1;
    }

    // Mach-O Parsing
    [fi architectures];
    [fi isMissingPageZero];
    [fi infoPlist];
  }

  if (num_fds_pre != get_num_fds()) {
    abort();
  }

  return 0;
}
