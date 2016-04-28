/// Copyright 2015 Google Inc. All rights reserved.
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

#import "NSData+Zlib.h"

#include <zlib.h>

@implementation NSData (Zlib)

- (NSData *)compressIncludingGzipHeader:(BOOL)includeHeader {
  if ([self length]) {
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = (uint)[self length];
    stream.next_in = (Bytef *)[self bytes];
    stream.total_out = 0;
    stream.avail_out = 0;

    NSUInteger chunkSize = 16384;

    int windowSize = 15;
    if (includeHeader) {
      windowSize += 16;
    }

    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION,
                     Z_DEFLATED, windowSize, 8, Z_DEFAULT_STRATEGY) == Z_OK) {
      NSMutableData *data = [NSMutableData dataWithLength:chunkSize];
      while (stream.avail_out == 0) {
        if (stream.total_out >= [data length]) {
          data.length += chunkSize;
        }
        stream.next_out = (uint8_t *)[data mutableBytes] + stream.total_out;
        stream.avail_out = (uInt)([data length] - stream.total_out);
        deflate(&stream, Z_FINISH);
      }
      deflateEnd(&stream);
      data.length = stream.total_out;
      return data;
    }
  }
  return nil;
}

- (NSData *)zlibCompressed {
  return [self compressIncludingGzipHeader:NO];
}

- (NSData *)gzipCompressed {
  return [self compressIncludingGzipHeader:YES];
}

@end
