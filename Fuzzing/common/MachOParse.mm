#import <Foundation/Foundation.h>
#include <stddef.h>
#include <stdint.h>

#import "Source/common/SNTFileInfo.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static NSString *tmpPath =
    [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];

  @autoreleasepool {
    assert([[NSFileManager defaultManager] createFileAtPath:tmpPath
                                                   contents:[NSData dataWithBytes:data length:size]
                                                 attributes:nil]);
    NSError *error;
    SNTFileInfo *fi = [[SNTFileInfo alloc] initWithResolvedPath:tmpPath error:&error];
    if (!fi || error != nil) {
      NSLog(@"Error: %@", error);
      return -1;
    }

    // Mach-O Parsing
    [fi architectures];  // forces machHeaders evaluation
    [fi isMissingPageZero];
  }

  return 0;
}
