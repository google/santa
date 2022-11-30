/// Copyright 2021 Google Inc. All rights reserved.
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

#import "Source/santametricservice/Writers/SNTMetricFileWriter.h"
#import "Source/common/SNTLogging.h"

@implementation SNTMetricFileWriter

/*
 * Open a file for appending.
 */
- (NSFileHandle *)fileHandleForNewFileAtPath:(NSString *)path createMode:(mode_t)mode {
  int fd;
  if (!path) {
    return nil;
  }

  fd = open([path fileSystemRepresentation], O_WRONLY | O_APPEND | O_TRUNC | O_CREAT, mode);
  if (fd < 0) {
    return nil;
  }
  return [[NSFileHandle alloc] initWithFileDescriptor:fd closeOnDealloc:YES];
}

/**
 * Write serialzied metrics to the file one JSON object per line.
 **/
- (BOOL)write:(NSArray<NSData *> *)metrics toURL:(NSURL *)url error:(NSError **)error {
  // open the file and write it.
  @autoreleasepool {
    if (![url isFileURL]) {
      LOGE(@"url supplied to SNTMetricFileOutput is not a file url, given %@", url.absoluteString);
      return NO;
    }

    NSFileHandle *file = [self fileHandleForNewFileAtPath:url.path createMode:0600];
    const char newline[1] = {'\n'};

    if (file == nil) {
      LOGE(@"Unable to open file %@ to write metrics", url.path);
      return NO;
    }

    NSMutableData *entryData;

    for (id formattedMetricData in metrics) {
      entryData = [NSMutableData dataWithData:formattedMetricData];

      [entryData appendBytes:newline length:1];

      if (![file writeData:entryData error:error]) {
        return NO;
      }
    }
  }

  return YES;
}

@end
