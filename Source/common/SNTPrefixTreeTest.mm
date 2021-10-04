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

#include "Source/common/SNTPrefixTree.h"

@interface SNTPrefixTreeTest : XCTestCase
@end

@implementation SNTPrefixTreeTest

- (void)testAddAndHas {
  auto t = SNTPrefixTree();
  XCTAssertFalse(t.HasPrefix("/private/var/tmp/file1"));
  t.AddPrefix("/private/var/tmp/");
  XCTAssertTrue(t.HasPrefix("/private/var/tmp/file1"));
}

- (void)testReset {
  auto t = SNTPrefixTree();
  t.AddPrefix("/private/var/tmp/");
  XCTAssertTrue(t.HasPrefix("/private/var/tmp/file1"));
  t.Reset();
  XCTAssertFalse(t.HasPrefix("/private/var/tmp/file1"));
}

- (void)testThreading {
  uint32_t count = 4096;
  auto t = new SNTPrefixTree(count * (uint32_t)[NSUUID UUID].UUIDString.length);

  NSMutableArray *UUIDs = [NSMutableArray arrayWithCapacity:count];
  for (int i = 0; i < count; ++i) {
    [UUIDs addObject:[NSUUID UUID].UUIDString];
  }

  __block BOOL stop = NO;

  // Create a bunch of background noise.
  dispatch_async(dispatch_get_global_queue(0, 0), ^{
    for (uint64_t i = 0; i < UINT64_MAX; ++i) {
      t->HasPrefix([UUIDs[i % count] UTF8String]);
      if (stop) return;
    }
  });

  // Fill up the tree.
  dispatch_apply(count, dispatch_get_global_queue(0, 0), ^(size_t i) {
    XCTAssertEqual(t->AddPrefix([UUIDs[i] UTF8String]), kIOReturnSuccess);
  });

  // Make sure every leaf byte is found.
  dispatch_apply(count, dispatch_get_global_queue(0, 0), ^(size_t i) {
    XCTAssertTrue(t->HasPrefix([UUIDs[i] UTF8String]));
  });

  stop = YES;
}

@end
