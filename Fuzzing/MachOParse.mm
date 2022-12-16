#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stddef.h>

#import "Source/common/SNTFileInfo.h"

void FuzzOne(const uint8_t *data, size_t size) {
  @autoreleasepool {
    NSString *tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
    assert([[NSFileManager defaultManager] createFileAtPath:tmpPath contents:[NSData dataWithBytes:data length:size] attributes:nil]);
    NSError *error;
    SNTFileInfo *fi = [[SNTFileInfo alloc] initWithResolvedPath:tmpPath error:&error];
    if (!fi || error != nil) {
      NSLog(@"Error: %@", error);
      [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
      return;
    }

    // Hashing
    [fi SHA1];
    [fi SHA256];

    // Mach-O Parsing
    [fi architectures];  // forces machHeaders evaluation
    [fi isMissingPageZero];

    [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
  }
}
