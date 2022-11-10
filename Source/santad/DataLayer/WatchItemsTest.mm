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
#include <sys/syslimits.h>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <stack>
#include <vector>

#define SANTA_PREFIX_TREE_DEBUG 1
#include "Source/common/PrefixTree.h"
#include "Source/santad/DataLayer/WatchItems.h"

using santa::santad::data_layer::WatchItem;
using santa::santad::data_layer::WatchItemPolicy;
using santa::santad::data_layer::WatchItems;

namespace santa::santad::data_layer {

class WatchItemsPeer : public WatchItems {
 public:
  using WatchItems::WatchItems;
};

}  // namespace santa::santad::data_layer

using santa::santad::data_layer::WatchItemsPeer;

void pushd(std::stack<std::string> &dirStack, std::string dir) {
  char *buf = new char[PATH_MAX]();
  getcwd(buf, PATH_MAX);

  dirStack.push(buf);
  delete[] buf;

  chdir(dir.c_str());
}

void popd(std::stack<std::string> &dirStack) {
  chdir(dirStack.top().c_str());
  dirStack.pop();
}

auto print = [](const auto &v, std::string_view start = "", std::string_view end = "") {
  std::cout << start << "{ ";
  for (const auto &i : v)
    std::cout << i << ' ';
  std::cout << "} " << end;
};

@interface WatchItemsTest : XCTestCase
@property NSFileManager *fileMgr;
@property NSString *testDir;
@property dispatch_queue_t q;
@end

@implementation WatchItemsTest

- (void)setUp {
  self.fileMgr = [NSFileManager defaultManager];
  self.testDir =
    [NSString stringWithFormat:@"%@santa-watchitems-%d", NSTemporaryDirectory(), getpid()];

  XCTAssertTrue([self.fileMgr createDirectoryAtPath:self.testDir
                        withIntermediateDirectories:YES
                                         attributes:nil
                                              error:nil]);

  self.q = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
  XCTAssertNotNil(self.q);
}

- (void)tearDown {
  XCTAssertTrue([self.fileMgr removeItemAtPath:self.testDir error:nil]);
}

- (void)createDirStructure:(NSArray *)fs rootedAt:(NSString *)root {
  char *buf = new char[PATH_MAX]();
  getcwd(buf, PATH_MAX);
  chdir([root UTF8String]);

  for (id item in fs) {
    if ([item isKindOfClass:[NSString class]]) {
      XCTAssertTrue([self.fileMgr createFileAtPath:item contents:nil attributes:nil]);
    } else if ([item isKindOfClass:[NSDictionary class]]) {
      for (id dir in item) {
        XCTAssertTrue([item[dir] isKindOfClass:[NSArray class]]);
        XCTAssertTrue([self.fileMgr createDirectoryAtPath:dir
                              withIntermediateDirectories:NO
                                               attributes:nil
                                                    error:nil]);

        [self createDirStructure:item[dir] rootedAt:dir];
      }
    } else {
      XCTFail("Unexpected dir structure item: %@: %@", item, [item class]);
    }
  }

  chdir(buf);
  delete[] buf;
}

- (NSString *)createTestDirPath:(NSString *)path withRoot:(NSString *)root {
  return [NSString pathWithComponents:@[ self.testDir, root, path ]];
}

- (NSString *)createTestDirPath:(NSString *)path {
  return [NSString pathWithComponents:@[ self.testDir, path ]];
}

- (void)testBasic {
  NSArray *fs = @[
    @{
      @"a" : @[
        @{
          @"d1" : @[
            @"f1",
            @"f2",
            @{
              @"d1_nested" : @[],
            },
          ],
          @"d2" : @[
            @"f1",
          ]
        },
        @"f1",
        @"f2",
      ],
    },
    @{
      @"b" : @[
        @{
          @"d1" : @[
            @"f1",
            @"f2",
          ],
          @"d2" : @[
            @"f1",
          ]
        },
        @"f1",
      ],
    }
  ];
  fs = @[ @{
    @"a" : @[ @"f1", @"f2" ],
    @"b" : @[ @"f1", @"f2" ],
  } ];

  [self createDirStructure:fs rootedAt:self.testDir];

  std::stack<std::string> dirStack;
  WatchItemsPeer watchItems(@"config.plist", NULL);

  std::vector<std::shared_ptr<WatchItemPolicy>> configuredWatchItems1;
  std::vector<std::shared_ptr<WatchItemPolicy>> configuredWatchItems2;

  santa::common::PrefixTree<std::shared_ptr<WatchItemPolicy>> tree1;
  santa::common::PrefixTree<std::shared_ptr<WatchItemPolicy>> tree2;

  std::set<WatchItem> paths1;
  std::set<WatchItem> paths2;

  // Add initial set of items as "prefix" types
  configuredWatchItems1.push_back(std::make_shared<WatchItemPolicy>("wi2", "./*", false, true));

  pushd(dirStack, [[self createTestDirPath:@"a"] UTF8String]);
  watchItems.BuildPolicyTree(configuredWatchItems1, tree1, paths1);
  popd(dirStack);

  printf("First Generate...\n");
  tree1.Print();

  // Re-apply policy as "literal" types
  configuredWatchItems2.push_back(std::make_shared<WatchItemPolicy>("wi2", "./*"));

  pushd(dirStack, [[self createTestDirPath:@"b"] UTF8String]);
  watchItems.BuildPolicyTree(configuredWatchItems2, tree2, paths2);
  popd(dirStack);

  printf("Second Generate...\n");
  tree2.Print();

  std::set<WatchItem> removed_items;
  std::set_difference(paths1.begin(), paths1.end(), paths2.begin(), paths2.end(),
                      std::inserter(removed_items, removed_items.begin()));

  print(paths1, "paths1: ", "\n");
  print(paths2, "paths2: ", "\n");
  print(removed_items, "Diff: ", "\n");
}

@end
