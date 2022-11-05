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

#define SANTA_PREFIX_TREE_DEBUG 1
#include "Source/common/PrefixTree.h"

using santa::common::PrefixTree;

@interface PrefixTreeTest : XCTestCase
@end

@implementation PrefixTreeTest

- (void)testBasic {
  PrefixTree<int> tree;

  XCTAssertFalse(tree.HasPrefix("/foo/bar/baz"));
  XCTAssertFalse(tree.HasPrefix("/foo/bar.txt"));
  XCTAssertFalse(tree.HasPrefix("/baz"));

  XCTAssertTrue(tree.InsertPrefix("/foo", 12));
  XCTAssertTrue(tree.InsertPrefix("/bar", 34));
  XCTAssertTrue(tree.InsertLiteral("/foo/bar", 56));

  // Re-inserting something that exists is allowed
  XCTAssertTrue(tree.InsertLiteral("/foo", 78));
  XCTAssertTrue(tree.InsertPrefix("/foo", 56));

  XCTAssertTrue(tree.HasPrefix("/foo/bar/baz"));
  XCTAssertTrue(tree.HasPrefix("/foo/bar.txt"));
  XCTAssertFalse(tree.HasPrefix("/baz"));
}

- (void)testHasPrefix {
  PrefixTree<int> tree;

  XCTAssertTrue(tree.InsertPrefix("/foo", 0));
  XCTAssertTrue(tree.InsertLiteral("/bar", 0));
  XCTAssertTrue(tree.InsertLiteral("/baz", 0));
  XCTAssertTrue(tree.InsertLiteral("/qaz", 0));

  // Check that a tree with a matching prefix is successful
  XCTAssertTrue(tree.HasPrefix("/foo.txt"));

  // This shouldn't succeed because `/bar` `/baz` and `qaz` are literals
  XCTAssertFalse(tree.HasPrefix("/bar.txt"));
  XCTAssertFalse(tree.HasPrefix("/baz.txt"));
  XCTAssertFalse(tree.HasPrefix("/qaz.txt"));

  // Now change `/bar` to a prefix type and retest HasPrefix
  // `/bar.txt` should now succeed, but `/baz.txt` should still not pass
  XCTAssertTrue(tree.InsertPrefix("/bar", 0));
  XCTAssertTrue(tree.HasPrefix("/bar.txt"));
  XCTAssertFalse(tree.HasPrefix("/baz.txt"));
  XCTAssertFalse(tree.HasPrefix("/qaz.txt"));

  // Insert a new prefix string to allow `/baz.txt` to have a valid prefix
  XCTAssertTrue(tree.InsertPrefix("/b", 0));
  XCTAssertTrue(tree.HasPrefix("/baz.txt"));
  XCTAssertFalse(tree.HasPrefix("/qaz.txt"));

  // An exact match on a literal allows HasPrefix to succeed
  XCTAssertTrue(tree.InsertLiteral("/qaz.txt", 0));
  XCTAssertTrue(tree.HasPrefix("/qaz.txt"));
}

- (void)testLookupLongestMatchingPrefix {
  PrefixTree<int> tree;

  XCTAssertTrue(tree.InsertPrefix("/foo", 12));
  XCTAssertTrue(tree.InsertPrefix("/bar", 34));
  XCTAssertTrue(tree.InsertPrefix("/foo/bar.txt", 56));

  std::optional<int> value;

  // Matching exact prefix
  value = tree.LookupLongestMatchingPrefix("/foo");
  XCTAssertEqual(value.value_or(0), 12);

  // Ensure changing node type works as expected
  // Literals must match exactly.
  value = tree.LookupLongestMatchingPrefix("/foo/bar.txt.tmp");
  XCTAssertEqual(value.value_or(0), 56);
  XCTAssertTrue(tree.InsertLiteral("/foo/bar.txt", 90));
  value = tree.LookupLongestMatchingPrefix("/foo/bar.txt.tmp");
  XCTAssertEqual(value.value_or(0), 12);

  // Inserting over an exiting node returns the new value
  XCTAssertTrue(tree.InsertPrefix("/foo", 78));
  value = tree.LookupLongestMatchingPrefix("/foo");
  XCTAssertEqual(value.value_or(0), 78);

  // No matching prefix
  value = tree.LookupLongestMatchingPrefix("/asdf");
  XCTAssertEqual(value.value_or(0), 0);
}

- (void)testNodeCounts {
  const uint32_t maxDepth = 100;
  PrefixTree<int> tree(100);

  XCTAssertEqual(tree.node_count_, 0);

  // Start with a small string
  XCTAssertTrue(tree.InsertPrefix("asdf", 0));
  XCTAssertEqual(tree.node_count_, 4);

  // Add a couple more characters to the existing string
  XCTAssertTrue(tree.InsertPrefix("asdfgh", 0));
  XCTAssertEqual(tree.node_count_, 6);

  // Inserting a string that exceeds max depth doesn't increase node count
  XCTAssertFalse(tree.InsertPrefix(std::string(maxDepth + 10, 'A').c_str(), 0));
  XCTAssertEqual(tree.node_count_, 6);

  // Add a new string that is a prefix of an existing string
  // This should increment the count by one since a new terminal node exists
  XCTAssertTrue(tree.InsertPrefix("as", 0));
  XCTAssertEqual(tree.node_count_, 7);

  // Re-inserting onto an existing node shouldn't modify the count
  tree.InsertLiteral("as", 0);
  tree.InsertPrefix("as", 0);
  XCTAssertEqual(tree.node_count_, 7);
}

- (void)testReset {
  // Ensure resetting a tree removes all content
  PrefixTree<int> tree;

  tree.Reset();
  XCTAssertEqual(tree.node_count_, 0);

  XCTAssertTrue(tree.InsertPrefix("asdf", 0));
  XCTAssertTrue(tree.InsertPrefix("qwerty", 0));

  XCTAssertTrue(tree.HasPrefix("asdf"));
  XCTAssertTrue(tree.HasPrefix("qwerty"));
  XCTAssertEqual(tree.node_count_, 10);

  tree.Reset();
  XCTAssertFalse(tree.HasPrefix("asdf"));
  XCTAssertFalse(tree.HasPrefix("qwerty"));
  XCTAssertEqual(tree.node_count_, 0);
}

- (void)testComplexValues {
  class Foo {
   public:
    Foo(int x) : x_(x) {}
    int X() { return x_; }

   private:
    int x_;
  };

  PrefixTree<std::shared_ptr<Foo>> tree;

  XCTAssertTrue(tree.InsertPrefix("foo", std::make_shared<Foo>(123)));
  XCTAssertTrue(tree.InsertPrefix("bar", std::make_shared<Foo>(456)));

  std::optional<std::shared_ptr<Foo>> value;
  value = tree.LookupLongestMatchingPrefix("foo");
  XCTAssertTrue(value.has_value() && value->get()->X() == 123);

  value = tree.LookupLongestMatchingPrefix("bar");
  XCTAssertTrue(value.has_value() && value->get()->X() == 456);

  value = tree.LookupLongestMatchingPrefix("asdf");
  XCTAssertFalse(value.has_value());
}

- (void)testThreading {
  uint32_t count = 4096;
  auto t = new PrefixTree<int>(count * (uint32_t)[NSUUID UUID].UUIDString.length);

  NSMutableArray *UUIDs = [NSMutableArray arrayWithCapacity:count];
  for (int i = 0; i < count; ++i) {
    [UUIDs addObject:[NSUUID UUID].UUIDString];
  }

  __block BOOL stop = NO;

  // Create a bunch of background noise.
  dispatch_async(dispatch_get_global_queue(0, 0), ^{
    for (uint64_t i = 0; i < UINT64_MAX; ++i) {
      dispatch_async(dispatch_get_global_queue(0, 0), ^{
        t->HasPrefix([UUIDs[i % count] UTF8String]);
      });
      if (stop) return;
    }
  });

  // Fill up the tree.
  dispatch_apply(count, dispatch_get_global_queue(0, 0), ^(size_t i) {
    XCTAssertEqual(t->InsertPrefix([UUIDs[i] UTF8String], 0), true);
  });

  // Make sure every leaf byte is found.
  dispatch_apply(count, dispatch_get_global_queue(0, 0), ^(size_t i) {
    XCTAssertTrue(t->HasPrefix([UUIDs[i] UTF8String]));
  });

  stop = YES;
}

@end
