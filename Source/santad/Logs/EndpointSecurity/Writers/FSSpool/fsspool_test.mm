/// Copyright 2022 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#include <memory>

#include "Source/common/TestUtils.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool_log_batch_writer.h"
#include "google/protobuf/any.pb.h"
#include "google/protobuf/timestamp.pb.h"

namespace fsspool {

class FsSpoolWriterPeer : public FsSpoolWriter {
 public:
  // Constructors
  using FsSpoolWriter::FsSpoolWriter;

  // Private Methods
  using FsSpoolWriter::BuildDirectoryStructureIfNeeded;
  using FsSpoolWriter::EstimateSpoolDirSize;

  // Private member variables
  using FsSpoolWriter::spool_size_estimate_;
};

}  // namespace fsspool

using fsspool::FsSpoolLogBatchWriter;
using fsspool::FsSpoolWriterPeer;

static constexpr size_t kSpoolSize = 1048576;

#define XCTAssertStatusOk(s) XCTAssertTrue((s).ok())
#define XCTAssertStatusNotOk(s) XCTAssertFalse((s).ok())

google::protobuf::Any TestAnyTimestamp(int64_t s, int32_t n) {
  google::protobuf::Timestamp v;
  v.set_seconds(s);
  v.set_nanos(n);
  google::protobuf::Any any;
  any.PackFrom(v);
  return any;
}

@interface FSSpoolTest : XCTestCase
@property NSString *testDir;
@property NSString *baseDir;
@property NSString *spoolDir;
@property NSString *tmpDir;
@property NSFileManager *fileMgr;
@end

@implementation FSSpoolTest

- (void)setUp {
  self.testDir = [NSString stringWithFormat:@"%@fsspool-%d", NSTemporaryDirectory(), getpid()];
  self.baseDir = [NSString stringWithFormat:@"%@/base", self.testDir];
  self.spoolDir = [NSString stringWithFormat:@"%@/new", self.baseDir];
  self.tmpDir = [NSString stringWithFormat:@"%@/tmp", self.baseDir];

  self.fileMgr = [NSFileManager defaultManager];

  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.baseDir]);
  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.spoolDir]);
  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.tmpDir]);

  XCTAssertTrue([self.fileMgr createDirectoryAtPath:self.testDir
                        withIntermediateDirectories:YES
                                         attributes:nil
                                              error:nil]);
}

- (void)tearDown {
  XCTAssertTrue([self.fileMgr removeItemAtPath:self.testDir error:nil]);
}

- (void)testEstimateSpoolDirSize {
  NSString *testData = @"What a day for some testing!";
  NSString *largeTestData = RepeatedString(@"A", 10240);
  NSString *path = [NSString stringWithFormat:@"%@/%@", self.spoolDir, @"temppy.log"];
  NSString *emptyPath = [NSString stringWithFormat:@"%@/%@", self.spoolDir, @"empty.log"];
  auto writer = std::make_unique<FsSpoolWriterPeer>([self.baseDir UTF8String], kSpoolSize);

  // Create the spool dir structure and ensure no files exist
  XCTAssertStatusOk(writer->BuildDirectoryStructureIfNeeded());
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:nil] count], 0);

  // Ensure that the initial spool dir estimate is 0
  auto status = writer->EstimateSpoolDirSize();
  XCTAssertStatusOk(status);
  XCTAssertEqual(*status, 0);

  // Force the current estimate to be 0 since we're not recomputing on first write.
  writer->spool_size_estimate_ = *status;

  XCTAssertTrue([testData writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil]);

  // Ensure the test file was created
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:nil] count], 1);

  // Ensure the spool size estimate has grown at least as much as the content length
  status = writer->EstimateSpoolDirSize();
  XCTAssertStatusOk(status);
  // Update the current estimate
  writer->spool_size_estimate_ = *status;
  XCTAssertGreaterThanOrEqual(writer->spool_size_estimate_, testData.length);

  // Modify file contents without modifying spool directory mtime
  NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:path];
  [fileHandle seekToEndOfFile];
  [fileHandle writeData:[largeTestData dataUsingEncoding:NSUTF8StringEncoding]];
  [fileHandle closeFile];

  // Ensure only one file still exists
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:nil] count], 1);

  // Ensure that the returned estimate is the same as the old since mtime didn't change
  status = writer->EstimateSpoolDirSize();
  XCTAssertStatusOk(status);
  // Check that the current estimate is the same as the old estimate
  XCTAssertEqual(*status, writer->spool_size_estimate_);

  // Create a second file in the spool dir to bump mtime
  XCTAssertTrue([@"" writeToFile:emptyPath atomically:YES encoding:NSUTF8StringEncoding error:nil]);
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:nil] count], 2);

  status = writer->EstimateSpoolDirSize();
  XCTAssertStatusOk(status);

  // Ensure the newly returned size is appropriate
  XCTAssertGreaterThanOrEqual(*status, testData.length + largeTestData.length);
}

- (void)testSimpleWrite {
  auto writer = std::make_unique<FsSpoolWriterPeer>([self.baseDir UTF8String], kSpoolSize);

  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.baseDir]);
  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.spoolDir]);
  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.tmpDir]);

  std::string testData = "Good morning. This is some nice test data.";
  XCTAssertStatusOk(writer->WriteMessage(testData));

  NSError *err = nil;
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.tmpDir error:&err] count], 0);
  XCTAssertNil(err);
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:&err] count], 1);
  XCTAssertNil(err);
}

- (void)testSpoolFull {
  auto writer = std::make_unique<FsSpoolWriterPeer>([self.baseDir UTF8String], kSpoolSize);
  const std::string largeMessage(kSpoolSize + 1, '\x42');

  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.baseDir]);
  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.spoolDir]);
  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.tmpDir]);

  // Write the first message. This will make the spool directory larger than the max.
  XCTAssertStatusOk(writer->WriteMessage(largeMessage));

  // Ensure the files are created
  XCTAssertTrue([self.fileMgr fileExistsAtPath:self.baseDir]);
  XCTAssertTrue([self.fileMgr fileExistsAtPath:self.spoolDir]);
  XCTAssertTrue([self.fileMgr fileExistsAtPath:self.tmpDir]);

  NSError *err = nil;
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.tmpDir error:&err] count], 0);
  XCTAssertNil(err);
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:&err] count], 1);
  XCTAssertNil(err);

  // Try to write again, but expect failure. File counts shouldn't change.
  XCTAssertStatusNotOk(writer->WriteMessage(largeMessage));

  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.tmpDir error:&err] count], 0);
  XCTAssertNil(err);
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:&err] count], 1);
  XCTAssertNil(err);
}

- (void)testWriteMessageNoFlush {
  auto writer = std::make_unique<FsSpoolWriterPeer>([self.baseDir UTF8String], kSpoolSize);
  FsSpoolLogBatchWriter batch_writer(writer.get(), 10);

  // Ensure that writing in batch mode doesn't flsuh on individual writes.
  XCTAssertStatusOk(batch_writer.WriteMessage(TestAnyTimestamp(123, 456)));

  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.baseDir]);
  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.spoolDir]);
  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.tmpDir]);
}

- (void)testWriteMessageFlushAtCapacity {
  static const int kCapacity = 5;
  auto writer = std::make_unique<FsSpoolWriterPeer>([self.baseDir UTF8String], kSpoolSize);
  FsSpoolLogBatchWriter batch_writer(writer.get(), kCapacity);

  // Ensure batch flushed once capacity exceeded
  for (int i = 0; i < kCapacity + 1; i++) {
    XCTAssertStatusOk(batch_writer.WriteMessage(TestAnyTimestamp(123, 456)));
  }

  NSError *err = nil;
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.tmpDir error:&err] count], 0);
  XCTAssertNil(err);
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:&err] count], 1);
  XCTAssertNil(err);
}

- (void)testWriteMessageMultipleFlush {
  static const int kCapacity = 5;
  static const int kExpectedFlushes = 3;

  auto writer = std::make_unique<FsSpoolWriterPeer>([self.baseDir UTF8String], kSpoolSize);
  FsSpoolLogBatchWriter batch_writer(writer.get(), kCapacity);

  // Ensure batch flushed expected number of times
  for (int i = 0; i < kExpectedFlushes * kCapacity + 1; i++) {
    XCTAssertStatusOk(batch_writer.WriteMessage(TestAnyTimestamp(123, 456)));
  }

  NSError *err = nil;
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.tmpDir error:&err] count], 0);
  XCTAssertNil(err);
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:&err] count],
                 kExpectedFlushes);
  XCTAssertNil(err);
}

- (void)testWriteMessageFlushOnDestroy {
  static const int kCapacity = 10;
  static const int kNumberOfWrites = 7;

  auto writer = std::make_unique<FsSpoolWriterPeer>([self.baseDir UTF8String], kSpoolSize);

  {
    // Extra scope to enforce early destroy of batch_writer.
    FsSpoolLogBatchWriter batch_writer(writer.get(), kCapacity);
    for (int i = 0; i < kNumberOfWrites; i++) {
      XCTAssertStatusOk(batch_writer.WriteMessage(TestAnyTimestamp(123, 456)));
    }

    // Ensure nothing was written yet
    XCTAssertFalse([self.fileMgr fileExistsAtPath:self.baseDir]);
    XCTAssertFalse([self.fileMgr fileExistsAtPath:self.spoolDir]);
    XCTAssertFalse([self.fileMgr fileExistsAtPath:self.tmpDir]);
  }

  // Ensure the write happens when FsSpoolLogBatchWriter destructed
  NSError *err = nil;
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.tmpDir error:&err] count], 0);
  XCTAssertNil(err);
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:&err] count], 1);
  XCTAssertNil(err);
}

@end
