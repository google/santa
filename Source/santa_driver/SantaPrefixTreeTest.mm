/// Copyright 2018 Google Inc. All rights reserved.
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

#include "Source/santa_driver/SantaPrefixTree.h"

@interface SantaPrefixTreeTest : XCTestCase
@end

@implementation SantaPrefixTreeTest

- (void)testAddAndHas {
  auto t = SantaPrefixTree();
  XCTAssertFalse(t.HasPrefix("/private/var/tmp/file1"));
  t.AddPrefix("/private/var/tmp/");
  XCTAssertTrue(t.HasPrefix("/private/var/tmp/file1"));
}

- (void)testReset {
  auto t = SantaPrefixTree();
  t.AddPrefix("/private/var/tmp/");
  XCTAssertTrue(t.HasPrefix("/private/var/tmp/file1"));
  t.Reset();
  XCTAssertFalse(t.HasPrefix("/private/var/tmp/file1"));
}

- (void)testThreading {
  uint32_t count = 4096;
  auto t = new SantaPrefixTree(count * (uint32_t)[NSUUID UUID].UUIDString.length);

  NSMutableArray *UUIDs = [NSMutableArray arrayWithCapacity:count];
  for (int i = 0; i < count; ++i) {
    [UUIDs addObject:[NSUUID UUID].UUIDString];
  }

  // Create a bunch of background noise.
  dispatch_async(dispatch_get_global_queue(0, 0), ^{
    dispatch_apply(UINT64_MAX, dispatch_get_global_queue(0, 0), ^(size_t i) {
      t->HasPrefix([UUIDs[i % count] UTF8String]);
    });
  });

  // Fill up the tree.
  dispatch_apply(count, dispatch_get_global_queue(0, 0), ^(size_t i) {
    if (t->AddPrefix([UUIDs[i] UTF8String]) != kIOReturnSuccess) {
      XCTFail();
    }
  });

  // Make sure every leaf byte is found.
  dispatch_apply(count, dispatch_get_global_queue(0, 0), ^(size_t i) {
    if (!t->HasPrefix([UUIDs[i] UTF8String])) {
      XCTFail();
    }
  });
}

@end
