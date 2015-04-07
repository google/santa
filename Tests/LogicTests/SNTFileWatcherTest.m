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

static int unusedFd1 = -1;
static int unusedFd2 = -1;

+ (void)setUp {
  // xctest redirects the stdout/stderr FDs when starting tests. This is not a problem, except
  // xctool intercepts stdout/stderr FDs (1 & 2) to put them in nice sections of the output.
  // This causes problems with tests that write to files and is 'fixed' by opening two FDs just
  // to be safe. Unfortunately this means that anything printed (e.g. with printf or NSLog) will
  // not actually be printed in xctool output for this test suite, ho hum.
  unusedFd1 = open("/dev/null", O_WRONLY);
  unusedFd2 = open("/dev/null", O_WRONLY);
}

+ (void)tearDown {
  close(unusedFd1);
  close(unusedFd2);
}

- (void)setUp {
  [super setUp];

  self.fm = [NSFileManager defaultManager];
  self.file = @"/tmp/SNTFileWatcherTest_File";
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
                                                                  handler:^{
      [exp fulfill];
  }];
  [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testInitNewFile {
  [self deleteFile];

  __weak XCTestExpectation *exp = [self expectationWithDescription:@"Init: callback called"];
  __unused SNTFileWatcher *sut = [[SNTFileWatcher alloc] initWithFilePath:self.file
                                                                  handler:^{
      [exp fulfill];
  }];

  [self createFile];
  [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testFileChanged {
  __weak XCTestExpectation *exp = [self expectationWithDescription:@"Changed: callback called"];
  __unused SNTFileWatcher *sut = [[SNTFileWatcher alloc] initWithFilePath:self.file
                                                                  handler:^{
      NSString *d = [NSString stringWithContentsOfFile:self.file
                                              encoding:NSUTF8StringEncoding
                                                 error:nil];
      if ([d isEqual:@"0x8BADF00D"]) {
        [exp fulfill];
      }
  }];

  [[@"0x8BADF00D" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:self.file atomically:NO];
  [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testFileReplaced {
  __weak XCTestExpectation *exp = [self expectationWithDescription:@"Replaced: callback called"];
  __unused SNTFileWatcher *sut = [[SNTFileWatcher alloc] initWithFilePath:self.file
                                                                  handler:^{
      NSString *d = [NSString stringWithContentsOfFile:self.file
                                              encoding:NSUTF8StringEncoding
                                                 error:nil];
      if ([d isEqual:@"0xFACEFEED"]) {
        [exp fulfill];
      }
  }];

  [[@"0xFACEFEED" dataUsingEncoding:NSUTF8StringEncoding] writeToFile:self.file atomically:YES];

  [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testFileExtended {
  int fd = open(self.file.fileSystemRepresentation, O_WRONLY);
  write(fd, "0xDEAD", 6);

  __weak XCTestExpectation *exp = [self expectationWithDescription:@"Extended: callback called"];
  __unused SNTFileWatcher *sut = [[SNTFileWatcher alloc] initWithFilePath:self.file
                                                                  handler:^{
      int file = open(self.file.fileSystemRepresentation, O_RDONLY);
      char fileData[10];
      read(file, fileData, 10);

      if (strncmp(fileData, "0xDEADBEEF", 10) == 0) {
        [exp fulfill];
      }
  }];

  write(fd, "BEEF", 4);
  close(fd);

  [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

@end

