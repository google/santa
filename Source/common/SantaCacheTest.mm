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

  sut.Set(72057611258548992llu, 10000192);
  XCTAssertEqual(sut.Get(72057611258548992llu), 10000192);
}

- (void)testCacheRemove {
  auto sut = SantaCache<uint64_t, uint64_t>();

  sut.Set(0xDEADBEEF, 42);
  sut.Remove(0xDEADBEEF);

  XCTAssertEqual(sut.Get(0xDEADBEEF), 0);
}

- (void)testCacheResetAtLimit {
  auto sut = SantaCache<uint64_t, uint64_t>(5);

  sut.Set(1, 42);
  sut.Set(2, 42);
  sut.Set(3, 42);
  sut.Set(4, 42);
  sut.Set(5, 42);
  XCTAssertEqual(sut.Get(3), 42);
  sut.Set(6, 42);
  XCTAssertEqual(sut.Get(3), 0);
  XCTAssertEqual(sut.Get(6), 42);
}

- (void)testThreading {
  auto sut = new SantaCache<uint64_t, uint64_t>();

  for (int x = 0; x < 200; ++x) {
    dispatch_group_t group = dispatch_group_create();

    dispatch_group_enter(group);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
      for (int i = 0; i < 5000; ++i)
        sut->Set(i, 10000 - i);
      dispatch_group_leave(group);
    });

    dispatch_group_enter(group);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
      for (int i = 5000; i < 10000; ++i)
        sut->Set(i, 10000 - i);
      dispatch_group_leave(group);
    });

    if (dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
      XCTFail("Timed out while setting values for test");
    }

    for (int i = 0; i < 10000; ++i)
      XCTAssertEqual(sut->Get(i), 10000 - i);
  }

  delete sut;
}

- (void)testCount {
  auto sut = SantaCache<uint64_t, int>();

  XCTAssertEqual(sut.Count(), 0);

  sut.Set(4012, 42);
  sut.Set(42, 0);
  sut.Set(0x8BADF00D, 40010);

  XCTAssertEqual(sut.Count(), 2);
}

- (void)testDoubles {
  auto sut = SantaCache<double, double>();

  sut.Set(3.14, 2.718281);
  sut.Set(1.41429, 2.5029);
  sut.Set(4.6692, 1.2020569);
  sut.Set(1.61803398, 0.57721);

  XCTAssertEqual(sut.Count(), 4);
  XCTAssertEqual(sut.Get(3.14), 2.718281);
  XCTAssertEqual(sut.Get(1.41429), 2.5029);
  XCTAssertEqual(sut.Get(4.6692), 1.2020569);
  XCTAssertEqual(sut.Get(1.61803398), 0.57721);

  XCTAssertEqual(sut.Get(5.5555), 0);
  XCTAssertEqual(sut.Get(3.1459124), 0);
}

- (void)testStrings {
  auto sut = SantaCache<std::string, std::string>();

  std::string s1 = "foo";
  std::string s2 = "bar";

  sut.Set(s1, "deadbeef");
  sut.Set(s2, "feedface");

  XCTAssertEqual(sut.Count(), 2);
  XCTAssertEqual(sut.Get(s1), "deadbeef");
  XCTAssertEqual(sut.Get(s2), "feedface");

  sut.Remove(s2);

  XCTAssertTrue(sut.Get(s2).empty());
}

- (void)testCompareAndSwap {
  auto sut = SantaCache<uint64_t, uint64_t>(100);

  sut.Set(1, 42);
  sut.Set(1, 666, 1);
  sut.Set(1, 666, 0);
  XCTAssertEqual(sut.Get(1), 42);

  sut.Set(1, 0);
  XCTAssertEqual(sut.Get(1), 0);

  sut.Set(1, 42, 1);
  XCTAssertEqual(sut.Get(1), 0);

  sut.Set(1, 42, 0);
  XCTAssertEqual(sut.Get(1), 42);

  sut.Set(1, 0, 666);
  XCTAssertEqual(sut.Get(1), 42);
  sut.Set(1, 0, 42);
  XCTAssertEqual(sut.Get(1), 0);
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
  sut.Set(s1, 10);
  sut.Set(s2, 20);
  sut.Set(s3, 30);

  XCTAssertEqual(sut.Get(s1), 10);
  XCTAssertEqual(sut.Get(s2), 20);
  XCTAssertEqual(sut.Get(s3), 30);
}

@end
