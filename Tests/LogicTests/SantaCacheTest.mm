/// Copyright 2016 Google Inc. All rights reserved.
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

#include <string>

#include "SantaCache.h"

@interface SantaCacheTest : XCTestCase
@end

@implementation SantaCacheTest

- (void)setUp {
  self.continueAfterFailure = NO;
}

- (void)testSetAndGet {
  auto sut = new SantaCache<uint64_t>();

  sut->set(72057611258548992llu, 10000192);
  XCTAssertEqual(sut->get(72057611258548992llu), 10000192);

  delete sut;
}

- (void)testCacheRemove {
  auto sut = new SantaCache<uint64_t>();

  sut->set(0xDEADBEEF, 42);
  sut->remove(0xDEADBEEF);

  XCTAssertEqual(sut->get(0xDEADBEEF), 0);

  delete sut;
}

- (void)testBucketGrowCopy {
  auto sut = new SantaCache<uint64_t>();

  sut->set(386, 42);
  sut->set(2434, 42);

  XCTAssertEqual(sut->get(386), 42);
  XCTAssertEqual(sut->get(2434), 42);

  delete sut;
}

- (void)testBucketShrinkCopy {
  auto sut = new SantaCache<uint64_t>(100, 1);

  sut->set(386, 42);
  sut->set(2434, 42);
  sut->set(4482, 42);

  sut->remove(2434);

  XCTAssertEqual(sut->get(386), 42);
  XCTAssertEqual(sut->get(2434), 0);
  XCTAssertEqual(sut->get(4482), 42);

  delete sut;
}

- (void)testCacheResetAtLimit {
  auto sut = new SantaCache<uint64_t>(5);
  
  sut->set(1, 42);
  sut->set(2, 42);
  sut->set(3, 42);
  sut->set(4, 42);
  sut->set(5, 42);
  XCTAssertEqual(sut->get(3), 42);
  sut->set(6, 42);
  XCTAssertEqual(sut->get(3), 0);
  XCTAssertEqual(sut->get(6), 42);

  delete sut;
}

- (void)testThreading {
  auto sut = new SantaCache<uint64_t>();

  for (int x = 0; x < 200; ++x) {
    dispatch_group_t group = dispatch_group_create();

    dispatch_group_enter(group);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
      for (int i = 0; i < 5000; ++i) sut->set(i, 10000-i);
      dispatch_group_leave(group);
    });

    dispatch_group_enter(group);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
      for (int i = 5000; i < 10000; ++i) sut->set(i, 10000-i);
      dispatch_group_leave(group);
    });

    if (dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
      XCTFail("Timed out while setting values for test");
    }

    for (int i = 0; i < 10000; ++i) XCTAssertEqual(sut->get(i), 10000 - i);
  }

  delete sut;
}

- (void)testCount {
  auto sut = new SantaCache<uint64_t>();

  XCTAssertEqual(sut->count(), 0);

  sut->set(4012, 42);
  sut->set(42, 0);  
  sut->set(0x8BADF00D, 40010);

  XCTAssertEqual(sut->count(), 2);

  delete sut;
}

- (void)testStrings {
  auto sut = new SantaCache<std::string>();

  sut->set(1, "deadbeef");
  sut->set(2, "feedface");

  XCTAssertEqual(sut->count(), 2);
  XCTAssertEqual(sut->get(1), "deadbeef");
  XCTAssertEqual(sut->get(2), "feedface");

  sut->remove(2);

  XCTAssertTrue(sut->get(2).empty());

  delete sut;
}

@end
