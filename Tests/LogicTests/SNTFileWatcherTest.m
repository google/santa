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

#import <XCTest/XCTest.h>

#import "SNTFileWatcher.h"

@interface SNTFileWatcherTest : XCTestCase
@property NSFileManager *fm;
@property NSString *file;
@end

@implementation SNTFileWatcherTest

- (void)setUp {
  [super setUp];

  self.fm = [NSFileManager defaultManager];
  self.file = [NSTemporaryDirectory() stringByAppendingString:@"SNTFileWatcherTest_File"];
  [self createFile];
  usleep(10000);
}

- (void)tearDown {
  [self deleteFile];
  usleep(10000);

  [super tearDown];
}

- (void)createFile {
  [self.fm createFileAtPath:self.file contents:nil attributes:nil];
}

- (void)deleteFile {
  [self.fm removeItemAtPath:self.file error:NULL];
}

- (void)testPlainInit {
  XCTAssertThrows([[SNTFileWatcher alloc] init]);
}

- (void)testInitFileExists {
  __weak XCTestExpectation *exp = [self expectationWithDescription:@"Init: callback called"];
  __unused SNTFileWatcher *sut = [[SNTFileWatcher alloc] initWithFilePath:self.file
                                                                  handler:^(unsigned long data) {
      [exp fulfill];
  }];
  [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testInitNewFile {
  [self deleteFile];

  __weak XCTestExpectation *exp = [self expectationWithDescription:@"Init: callback called"];
  __unused SNTFileWatcher *sut = [[SNTFileWatcher alloc] initWithFilePath:self.file
                                                                  handler:^(unsigned long data) {
      [exp fulfill];
  }];

  [self createFile];
  [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testFileChanged {
  __block BOOL fulfilled = NO;
  __weak XCTestExpectation *exp = [self expectationWithDescription:@"Changed: callback called"];
  __unused SNTFileWatcher *sut = [[SNTFileWatcher alloc] initWithFilePath:self.file
                                                                  handler:^(unsigned long data) {
      NSString *d = [NSString stringWithContentsOfFile:self.file
                                              encoding:NSUTF8StringEncoding
                                                 error:nil];
      if (!fulfilled && [d isEqual:@"0x8BADF00D"]) {
        fulfilled = YES;
        [exp fulfill];
      }
  }];

  sleep(1);

  [[@"0x8BADF00D" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:self.file atomically:NO];
  [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testFileReplaced {
  __block BOOL fulfilled = NO;
  __weak XCTestExpectation *exp = [self expectationWithDescription:@"Replaced: callback called"];
  __unused SNTFileWatcher *sut = [[SNTFileWatcher alloc] initWithFilePath:self.file
                                                                  handler:^(unsigned long data) {
      NSString *d = [NSString stringWithContentsOfFile:self.file
                                              encoding:NSUTF8StringEncoding
                                                 error:nil];
      if (!fulfilled && [d isEqual:@"0xFACEFEED"]) {
        fulfilled = YES;
        [exp fulfill];
      }
  }];

  [[@"0xFACEFEED" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:self.file atomically:YES];

  [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testFileExtended {
  int fd = open(self.file.fileSystemRepresentation, O_WRONLY);
  write(fd, "0xDEAD", 6);

  __block BOOL fulfilled = NO;
  __weak XCTestExpectation *exp = [self expectationWithDescription:@"Extended: callback called"];
  __unused SNTFileWatcher *sut = [[SNTFileWatcher alloc] initWithFilePath:self.file
                                                                  handler:^(unsigned long data) {
      int file = open(self.file.fileSystemRepresentation, O_RDONLY);
      char fileData[10];
      read(file, fileData, 10);

      if (!fulfilled && strncmp(fileData, "0xDEADBEEF", 10) == 0) {
        fulfilled = YES;
        [exp fulfill];
      }
  }];

  write(fd, "BEEF", 4);
  close(fd);

  [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

@end

