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

#import <XCTest/XCTest.h>

#include <numeric>
#include <string>
#include <vector>

#include "Source/common/SantaCache.h"

@interface SantaCacheTest : XCTestCase
@end

@implementation SantaCacheTest

- (void)setUp {
  self.continueAfterFailure = NO;
}

- (void)testSetAndGet {
  auto sut = SantaCache<uint64_t, uint64_t>();

  sut.set(72057611258548992llu, 10000192);
  XCTAssertEqual(sut.get(72057611258548992llu), 10000192);
}

- (void)testCacheRemove {
  auto sut = SantaCache<uint64_t, uint64_t>();

  sut.set(0xDEADBEEF, 42);
  sut.remove(0xDEADBEEF);

  XCTAssertEqual(sut.get(0xDEADBEEF), 0);
}

- (void)testCacheResetAtLimit {
  auto sut = SantaCache<uint64_t, uint64_t>(5);

  sut.set(1, 42);
  sut.set(2, 42);
  sut.set(3, 42);
  sut.set(4, 42);
  sut.set(5, 42);
  XCTAssertEqual(sut.get(3), 42);
  sut.set(6, 42);
  XCTAssertEqual(sut.get(3), 0);
  XCTAssertEqual(sut.get(6), 42);
}

- (void)testThreading {
  auto sut = new SantaCache<uint64_t, uint64_t>();

  for (int x = 0; x < 200; ++x) {
    dispatch_group_t group = dispatch_group_create();

    dispatch_group_enter(group);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
      for (int i = 0; i < 5000; ++i)
        sut->set(i, 10000 - i);
      dispatch_group_leave(group);
    });

    dispatch_group_enter(group);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
      for (int i = 5000; i < 10000; ++i)
        sut->set(i, 10000 - i);
      dispatch_group_leave(group);
    });

    if (dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
      XCTFail("Timed out while setting values for test");
    }

    for (int i = 0; i < 10000; ++i)
      XCTAssertEqual(sut->get(i), 10000 - i);
  }

  delete sut;
}

- (void)testCount {
  auto sut = SantaCache<uint64_t, int>();

  XCTAssertEqual(sut.count(), 0);

  sut.set(4012, 42);
  sut.set(42, 0);
  sut.set(0x8BADF00D, 40010);

  XCTAssertEqual(sut.count(), 2);
}

- (void)testDoubles {
  auto sut = SantaCache<double, double>();

  sut.set(3.14, 2.718281);
  sut.set(1.41429, 2.5029);
  sut.set(4.6692, 1.2020569);
  sut.set(1.61803398, 0.57721);

  XCTAssertEqual(sut.count(), 4);
  XCTAssertEqual(sut.get(3.14), 2.718281);
  XCTAssertEqual(sut.get(1.41429), 2.5029);
  XCTAssertEqual(sut.get(4.6692), 1.2020569);
  XCTAssertEqual(sut.get(1.61803398), 0.57721);

  XCTAssertEqual(sut.get(5.5555), 0);
  XCTAssertEqual(sut.get(3.1459124), 0);
}

- (void)testStrings {
  auto sut = SantaCache<std::string, std::string>();

  std::string s1 = "foo";
  std::string s2 = "bar";

  sut.set(s1, "deadbeef");
  sut.set(s2, "feedface");

  XCTAssertEqual(sut.count(), 2);
  XCTAssertEqual(sut.get(s1), "deadbeef");
  XCTAssertEqual(sut.get(s2), "feedface");

  sut.remove(s2);

  XCTAssertTrue(sut.get(s2).empty());
}

- (void)testCompareAndSwap {
  auto sut = SantaCache<uint64_t, uint64_t>(100);

  sut.set(1, 42);
  sut.set(1, 666, 1);
  sut.set(1, 666, 0);
  XCTAssertEqual(sut.get(1), 42);

  sut.set(1, 0);
  XCTAssertEqual(sut.get(1), 0);

  sut.set(1, 42, 1);
  XCTAssertEqual(sut.get(1), 0);

  sut.set(1, 42, 0);
  XCTAssertEqual(sut.get(1), 42);

  sut.set(1, 0, 666);
  XCTAssertEqual(sut.get(1), 42);
  sut.set(1, 0, 42);
  XCTAssertEqual(sut.get(1), 0);
}

struct S {
  uint64_t first_val;
  uint64_t second_val;

  bool operator==(const S &rhs) const {
    return first_val == rhs.first_val && second_val == rhs.second_val;
  }
};

template <>
struct std::hash<S> {
  std::size_t operator()(S const &s) const noexcept {
    return (std::hash<uint64_t>{}(s.first_val) << 1) ^ std::hash<uint64_t>{}(s.second_val);
  }
};

- (void)testStructKeys {
  auto sut = SantaCache<S, uint64_t>(10);

  S s1 = {1024, 2048};
  S s2 = {4096, 8192};
  S s3 = {16384, 32768};
  sut.set(s1, 10);
  sut.set(s2, 20);
  sut.set(s3, 30);

  XCTAssertEqual(sut.get(s1), 10);
  XCTAssertEqual(sut.get(s2), 20);
  XCTAssertEqual(sut.get(s3), 30);
}

@end
