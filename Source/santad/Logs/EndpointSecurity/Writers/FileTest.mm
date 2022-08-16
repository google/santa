/// Copyright 2022 Google Inc. All rights reserved.
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

#include <dispatch/dispatch.h>
#import <Foundation/Foundation.h>
#include <gtest/gtest.h>
#include <sys/stat.h>

#include <vector>

#include "Source/common/TestUtils.h"
#import "Source/santad/Logs/EndpointSecurity/Writers/File.h"

using santa::santad::logs::endpoint_security::writers::File;

namespace santa::santad::logs::endpoint_security::writers {

class FilePeer : public File {
public:
  // Make constructors visible
  using File::File;

  NSFileHandle* FileHandle() {
    return file_handle_;
  }

  void BeginWatchingLogFile() {
    WatchLogFile();
  }

  size_t InternalBufferSize() {
    return buffer_.size();
  }
};

} // namespace santa::santad::logs::endpoint_security::writers

using santa::santad::logs::endpoint_security::writers::FilePeer;

bool WaitFor(bool(^condition)(void)){
  int attempts = 0;
  long sleepPerAttemptMS = 10; // Wait 10ms between checks
  long maxSleep = 2000; // Wait up to 2 seconds for new log file to be created
  long maxAttempts = maxSleep / sleepPerAttemptMS;

  do {
    SleepMS(sleepPerAttemptMS);

    // Break out once the condition holds
    if (condition()) {
      break;
    }
  } while (++attempts < maxAttempts);

  return attempts < maxAttempts;
}

bool WaitForNewLogFile(NSFileManager* fileManager, NSString* path) {
  return WaitFor(^bool(){
    return [fileManager fileExistsAtPath:path];
  });
}

bool WaitForBufferSize(std::shared_ptr<FilePeer> file, size_t expectedSize) {
  return WaitFor(^bool(){
    return file->InternalBufferSize() == expectedSize;
  });
}

@interface FileTest : XCTestCase
@property NSString *path;
@property NSString *logPath;
@property NSString *logRenamePath;
@property dispatch_queue_t q;
@property dispatch_source_t timer;
@property NSFileManager *fileManager;
@end

@implementation FileTest

- (void)setUp {
  self.path = [NSString stringWithFormat:@"%@santa-%d",
                                     NSTemporaryDirectory(),
                                     getpid()];

  self.logPath = [NSString stringWithFormat:@"%@/log.out", self.path];
  self.logRenamePath = [NSString stringWithFormat:@"%@/log.rename.out", self.path];

  self.fileManager = [NSFileManager defaultManager];

  XCTAssertTrue([self.fileManager createDirectoryAtPath:self.path
                            withIntermediateDirectories:YES
                                             attributes:nil
                                                  error:nil]);

  self.q = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
  XCTAssertNotNil(self.q);
  self.timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  XCTAssertNotNil(self.timer);

  // Resume the timer to ensure its not inadvertently cancelled first
  dispatch_resume(self.timer);
}

- (void)tearDown {
  [self.fileManager removeItemAtPath:self.path error:nil];
}

- (void)testWatchLogFile {
  auto file = std::make_shared<FilePeer>(self.logPath, 100, 500, self.q, self.timer);
  file->BeginWatchingLogFile();

  // Constructing a File object will open the file at the given path
  struct stat wantSBOrig;
  struct stat gotSBOrig;
  XCTAssertEqual(stat([self.logPath UTF8String], &wantSBOrig), 0);
  XCTAssertEqual(fstat(file->FileHandle().fileDescriptor, &gotSBOrig), 0);
  XCTAssertEqual(wantSBOrig.st_ino, gotSBOrig.st_ino);

  // Deleting the current log file will cause a new file to be created
  XCTAssertTrue([self.fileManager removeItemAtPath:self.logPath error:nil]);

  XCTAssertTrue(WaitForNewLogFile(self.fileManager, self.logPath),
                "New log file not created within expected time after deletion");

  struct stat wantSBAfterDelete;
  struct stat gotSBAfterDelete;
  XCTAssertEqual(stat([self.logPath UTF8String], &wantSBAfterDelete), 0);
  XCTAssertEqual(fstat(file->FileHandle().fileDescriptor, &gotSBAfterDelete), 0);

  XCTAssertEqual(wantSBAfterDelete.st_ino, gotSBAfterDelete.st_ino);
  XCTAssertNotEqual(wantSBOrig.st_ino, wantSBAfterDelete.st_ino);

  // Renaming the current log file will cause a new file to be created
  XCTAssertTrue([self.fileManager moveItemAtPath:self.logPath
                                          toPath:self.logRenamePath
                                            error:nil]);

  XCTAssertTrue(WaitForNewLogFile(self.fileManager, self.logPath),
                "New log file not created within expected time after rename");

  struct stat wantSBAfterRename;
  struct stat gotSBAfterRename;
  XCTAssertEqual(stat([self.logPath UTF8String], &wantSBAfterRename), 0);
  XCTAssertEqual(fstat(file->FileHandle().fileDescriptor, &gotSBAfterRename), 0);

  XCTAssertEqual(wantSBAfterRename.st_ino, gotSBAfterRename.st_ino);
  XCTAssertNotEqual(wantSBAfterDelete.st_ino, wantSBAfterRename.st_ino);
}

- (void)testWrite {
  // Start with empty file. Perform two writes. The first will only go into the
  // internal buffer. The second will meet/exceed capacity and flush to disk
  size_t bufferSize = 100;
  size_t writeSize = 50;
  auto file = std::make_shared<FilePeer>(self.logPath,
                                         bufferSize,
                                         bufferSize * 2,
                                         self.q,
                                         self.timer);

  // Starting out, file size and internal buffer are 0
  struct stat gotSB;
  XCTAssertEqual(fstat(file->FileHandle().fileDescriptor, &gotSB), 0);
  XCTAssertEqual(0, gotSB.st_size);
  XCTAssertEqual(0, file->InternalBufferSize());

  // After the first write, the buffer is 50 bytes, but the file is still 0
  file->Write(std::vector<uint8_t>(writeSize, 'A'));
  WaitForBufferSize(file, 50);
  XCTAssertEqual(fstat(file->FileHandle().fileDescriptor, &gotSB), 0);
  XCTAssertEqual(0, gotSB.st_size);
  XCTAssertEqual(50, file->InternalBufferSize());

  // After the second write, the buffer is flushed. File size 100, buffer is 0.
  file->Write(std::vector<uint8_t>(writeSize, 'B'));
  WaitForBufferSize(file, 0);
  XCTAssertEqual(fstat(file->FileHandle().fileDescriptor, &gotSB), 0);
  XCTAssertEqual(100, gotSB.st_size);
  XCTAssertEqual(0, file->InternalBufferSize());
}

@end
