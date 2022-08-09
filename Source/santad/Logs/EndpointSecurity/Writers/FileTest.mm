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

#import <Foundation/Foundation.h>
#include <gtest/gtest.h>
#include <sys/stat.h>

#include <vector>

#import "Source/santad/Logs/EndpointSecurity/Writers/File.h"

using santa::santad::logs::endpoint_security::writers::File;

namespace santa::santad::logs::endpoint_security::writers {

class FileTest : public File {
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

using santa::santad::logs::endpoint_security::writers::FileTest;

class FileTestFixture : public testing::Test {
protected:
  FileTestFixture() {
    path_ = [NSString stringWithFormat:@"%@santa-%d",
                                       NSTemporaryDirectory(),
                                       getpid()];

    log_path_ = [NSString stringWithFormat:@"%@/log.out", path_];
    log_rename_path_ = [NSString stringWithFormat:@"%@/log.rename.out", path_];

    file_manager_ = [NSFileManager defaultManager];
  }

  ~FileTestFixture() {
    EXPECT_NE(0,
             [file_manager_ removeItemAtPath:path_ error:nil]);
  }
  void SetUp() override {
    // Create the temporary dir, and dispatch objects.
    ASSERT_NE(0,
              [file_manager_ createDirectoryAtPath:path_
                       withIntermediateDirectories:YES
                                        attributes:nil
                                             error:nil]);

    q_ = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
    ASSERT_NE(q_, nil);
    timer_ = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q_);
    ASSERT_NE(timer_, nil);

    // Resume the timer to ensure its not inadvertently cancelled first
    dispatch_resume(timer_);
  }

  NSString *path_;
  NSString *log_path_;
  NSString *log_rename_path_;
  dispatch_queue_t q_;
  dispatch_source_t timer_;
  NSFileManager *file_manager_;
};

bool WaitFor(bool(^condition)(void)){
  int attempts = 0;
  long sleep_per_attempt_ms = 10; // Wait 10ms between checks
  long max_sleep = 2000; // Wait up to 2 seconds for new log file to be created
  long max_attempts = max_sleep / sleep_per_attempt_ms;

  do {
    struct timespec ts {
      .tv_sec = 0,
      .tv_nsec = (long)(100 * NSEC_PER_MSEC),
    };

    // Account for interruption
    while (nanosleep(&ts, &ts) != 0) {}

    // Break out once the condition holds
    if (condition()) {
      break;
    }
  } while (++attempts < max_attempts);

  return attempts < max_attempts;
}

bool WaitForNewLogFile(NSFileManager* file_manager, NSString* path) {
  return WaitFor(^bool(){
    return [file_manager fileExistsAtPath:path];
  });
}

bool WaitForBufferSize(std::shared_ptr<FileTest> file, size_t expected_size) {
  return WaitFor(^bool(){
    return file->InternalBufferSize() == expected_size;
  });
}

TEST_F(FileTestFixture, WatchLogFile) {
  auto file = std::make_shared<FileTest>(log_path_, 100, 500, q_, timer_);
  file->BeginWatchingLogFile();

  // Constructing a File object will open the file at the given path
  struct stat orig_want_sb;
  struct stat orig_got_sb;
  ASSERT_EQ(stat([log_path_ UTF8String], &orig_want_sb), 0);
  ASSERT_EQ(fstat(file->FileHandle().fileDescriptor, &orig_got_sb), 0);
  ASSERT_EQ(orig_want_sb.st_ino, orig_got_sb.st_ino);

  // Deleting the current log file will cause a new file to be created
  ASSERT_TRUE([file_manager_ removeItemAtPath:log_path_ error:nil]);

  ASSERT_TRUE(WaitForNewLogFile(file_manager_, log_path_))
      << "New log file not created within expected time after deletion";

  struct stat after_delete_want_sb;
  struct stat after_delete_got_sb;
  ASSERT_EQ(stat([log_path_ UTF8String], &after_delete_want_sb), 0);
  ASSERT_EQ(fstat(file->FileHandle().fileDescriptor, &after_delete_got_sb), 0);

  ASSERT_EQ(after_delete_want_sb.st_ino, after_delete_got_sb.st_ino);
  ASSERT_NE(orig_want_sb.st_ino, after_delete_want_sb.st_ino);

  // Renaming the current log file will cause a new file to be created
  ASSERT_TRUE([file_manager_ moveItemAtPath:log_path_
                                     toPath:log_rename_path_
                                      error:nil]);

  ASSERT_TRUE(WaitForNewLogFile(file_manager_, log_path_))
      << "New log file not created within expected time after rename";

  struct stat after_rename_want_sb;
  struct stat after_rename_got_sb;
  ASSERT_EQ(stat([log_path_ UTF8String], &after_rename_want_sb), 0);
  ASSERT_EQ(fstat(file->FileHandle().fileDescriptor, &after_rename_got_sb), 0);

  ASSERT_EQ(after_rename_want_sb.st_ino, after_rename_got_sb.st_ino);
  ASSERT_NE(after_delete_want_sb.st_ino, after_rename_want_sb.st_ino);
}

TEST_F(FileTestFixture, Write) {
  // Start with empty file. Perform two writes. The first will only go into the
  // internal buffer. The second will meet/exceed capacity and flush to disk
  size_t buffer_size = 100;
  size_t write_size = 50;
  auto file = std::make_shared<FileTest>(log_path_,
                                         buffer_size,
                                         buffer_size * 2,
                                         q_,
                                         timer_);

  // Starting out, file size and internal buffer are 0
  struct stat got_sb;
  ASSERT_EQ(fstat(file->FileHandle().fileDescriptor, &got_sb), 0);
  ASSERT_EQ(0, got_sb.st_size);
  ASSERT_EQ(0, file->InternalBufferSize());

  // After the first write, the buffer is 50 bytes, but the file is still 0
  file->Write(std::vector<uint8_t>(write_size, 'A'));
  WaitForBufferSize(file, 50);
  ASSERT_EQ(fstat(file->FileHandle().fileDescriptor, &got_sb), 0);
  EXPECT_EQ(0, got_sb.st_size);
  EXPECT_EQ(50, file->InternalBufferSize());

  // After the second write, the buffer is flushed. File size 100, buffer is 0.
  file->Write(std::vector<uint8_t>(write_size, 'B'));
  WaitForBufferSize(file, 0);
  ASSERT_EQ(fstat(file->FileHandle().fileDescriptor, &got_sb), 0);
  EXPECT_EQ(100, got_sb.st_size);
  EXPECT_EQ(0, file->InternalBufferSize());
}
