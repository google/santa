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
#import <XCTest/XCTest.h>
#include <dispatch/dispatch.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include "Source/common/TestUtils.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Protobuf.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool_log_batch_writer.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Spool.h"

namespace santa::santad::logs::endpoint_security::writers {

class SpoolPeer : public Spool {
 public:
  // Make constructors visible
  using Spool::Spool;

  std::string GetTypeUrl() { return type_url_; }

  void StopPeriodicTask() {
    dispatch_suspend(timer_source_);
    flush_task_started_ = false;
  }
};

}  // namespace santa::santad::logs::endpoint_security::writers

using santa::santad::logs::endpoint_security::serializers::Protobuf;
using santa::santad::logs::endpoint_security::writers::SpoolPeer;

class MockProtobuf : public Protobuf {
 public:
  using Protobuf::Protobuf;
  MOCK_METHOD(bool, Drain, (std::string * output, size_t threshold));
};

@interface SpoolTest : XCTestCase
@property dispatch_queue_t q;
@property dispatch_source_t timer;
@property NSFileManager *fileMgr;
@property NSString *testDir;
@property NSString *baseDir;
@property NSString *spoolDir;
@end

@implementation SpoolTest

- (void)setUp {
  self.fileMgr = [NSFileManager defaultManager];
  self.testDir = [NSString stringWithFormat:@"%@santa-spool-%d", NSTemporaryDirectory(), getpid()];
  self.testDir = [NSString stringWithFormat:@"%@fsspool-%d", NSTemporaryDirectory(), getpid()];
  self.baseDir = [NSString stringWithFormat:@"%@/base", self.testDir];
  self.spoolDir = [NSString stringWithFormat:@"%@/new", self.baseDir];

  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.baseDir]);
  XCTAssertFalse([self.fileMgr fileExistsAtPath:self.spoolDir]);

  XCTAssertTrue([self.fileMgr createDirectoryAtPath:self.testDir
                        withIntermediateDirectories:YES
                                         attributes:nil
                                              error:nil]);

  self.q = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
  XCTAssertNotNil(self.q);
  self.timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  XCTAssertNotNil(self.timer);
}

- (void)tearDown {
  XCTAssertTrue([self.fileMgr removeItemAtPath:self.testDir error:nil]);
}

- (void)testTypeUrl {
  // Ensure the manually created type url isn't modified
  auto spool = std::make_shared<SpoolPeer>(nullptr, self.q, self.timer, [self.baseDir UTF8String],
                                           10240, 1024, 1);
  std::string wantTypeUrl("type.googleapis.com/santa.pb.v1.SantaMessageBatch");
  XCTAssertCppStringEqual(spool->GetTypeUrl(), wantTypeUrl);
}

- (void)testWrite {
  const uint64 periodicFlushMS = 400;
  const size_t max_file_size = 256;
  NSError *err = nil;

  bool (^DrainBlock)(std::string *, size_t) = ^bool(std::string *output, size_t threshold) {
    if (threshold > 0) {
      output->append(max_file_size, 'A');
      return true;
    } else {
      return false;
    }
  };

  // The mock is expected tp be called twice via the `Write` method and twice
  // via the periodic task. These calls are distinguished by the threshold arg.
  auto mockProtobuf = std::make_shared<MockProtobuf>(nullptr);
  EXPECT_CALL(*mockProtobuf, Drain(testing::_, max_file_size)).Times(2).WillRepeatedly(DrainBlock);
  EXPECT_CALL(*mockProtobuf, Drain(testing::_, 0)).Times(2).WillRepeatedly(DrainBlock);

  dispatch_semaphore_t semaWrite = dispatch_semaphore_create(0);
  dispatch_semaphore_t semaFlush = dispatch_semaphore_create(0);
  __block int flushCount = 0;

  auto spool = std::make_shared<SpoolPeer>(
    mockProtobuf, self.q, self.timer, [self.baseDir UTF8String], 10240, max_file_size, 1,
    ^{
      dispatch_semaphore_signal(semaWrite);
    },
    ^{
      printf("FLUSH FIRED\n");
      flushCount++;
      if (flushCount <= 2) {
        // The first flush is the initial fire.
        // The second flush should flush the new contents to disk
        // Afterwards, nothing else waits on the semaphore, so stop signaling
        dispatch_semaphore_signal(semaFlush);
      }
    });

  // Set a custom timer interval for this test
  dispatch_source_set_timer(self.timer, dispatch_time(DISPATCH_TIME_NOW, 0),
                            NSEC_PER_MSEC * periodicFlushMS, 0);

  spool->Write(std::vector<uint8_t>{});

  XCTAssertSemaTrue(semaWrite, 5, "First write didn't complete within expected window");

  // Sleep for a short time. Nothing should happen, but want to help ensure that if somehow
  // if somehow timers were active that would be caught and fail the test.
  sleep(1);

  // Ensure nothing exists yet because periodic flush been started
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:&err] count], 0);

  // Manual Flush
  XCTAssertTrue(spool->Flush());

  // A new log entry should exist
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:&err] count], 1);

  // Start the periodic flush task
  spool->BeginPeriodicTask();

  XCTAssertSemaTrue(semaFlush, 5, "Initial flush task firing didn't occur within expected window");

  // Ensure no growth in the amount of data
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:&err] count], 1);

  // Write a second log entry
  spool->Write(std::vector<uint8_t>{});

  XCTAssertSemaTrue(semaWrite, 5, "Second write didn't compelete within expected window");
  XCTAssertSemaTrue(semaFlush, 5, "Second flush task firing didn't occur within expected window");

  spool->StopPeriodicTask();

  // Ensure the new log entry appears
  XCTAssertEqual([[self.fileMgr contentsOfDirectoryAtPath:self.spoolDir error:&err] count], 2);
}

@end
