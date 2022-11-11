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
#include <vector>

#define SANTA_PREFIX_TREE_DEBUG 1
#include "Source/common/PrefixTree.h"
#include "Source/santad/DataLayer/WatchItems.h"

using santa::common::PrefixTree;
using santa::santad::data_layer::WatchItem;
using santa::santad::data_layer::WatchItemPolicy;
using santa::santad::data_layer::WatchItems;

namespace santa::santad::data_layer {

class WatchItemsPeer : public WatchItems {
 public:
  using WatchItems::BuildPolicyTree;
  using WatchItems::currently_monitored_paths_;
  using WatchItems::ReloadConfig;
  using WatchItems::WatchItems;
};

}  // namespace santa::santad::data_layer

using santa::santad::data_layer::WatchItemsPeer;

template <typename T>
void print(const T &v, std::string_view start = "", std::string_view end = "\n") {
  std::cout << start << "{ ";
  for (const auto &i : v)
    std::cout << i << ' ';
  std::cout << "} " << end;
};

@interface WatchItemsTest : XCTestCase
@property NSFileManager *fileMgr;
@property NSString *testDir;
@property NSMutableArray *dirStack;
@property dispatch_queue_t q;
@end

@implementation WatchItemsTest

- (void)setUp {
  self.dirStack = [[NSMutableArray alloc] init];
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

- (void)pushd:(NSString *)path withRoot:(NSString *)root {
  NSString *dir = [NSString pathWithComponents:@[ root, path ]];
  NSString *origCwd = [self.fileMgr currentDirectoryPath];
  XCTAssertNotNil(origCwd);

  XCTAssertTrue([self.fileMgr changeCurrentDirectoryPath:dir]);
  [self.dirStack addObject:origCwd];
}

- (void)pushd:(NSString *)dir {
  [self pushd:dir withRoot:self.testDir];
}

- (void)popd {
  NSString *dir = [self.dirStack lastObject];
  XCTAssertTrue([self.fileMgr changeCurrentDirectoryPath:dir]);
  [self.dirStack removeLastObject];
}

- (void)createTestDirStructure:(NSArray *)fs rootedAt:(NSString *)root {
  NSString *origCwd = [self.fileMgr currentDirectoryPath];
  XCTAssertNotNil(origCwd);
  XCTAssertTrue([self.fileMgr changeCurrentDirectoryPath:root]);

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

        [self createTestDirStructure:item[dir] rootedAt:dir];
      }
    } else {
      XCTFail("Unexpected dir structure item: %@: %@", item, [item class]);
    }
  }

  XCTAssertTrue([self.fileMgr changeCurrentDirectoryPath:origCwd]);
}

- (void)createTestDirStructure:(NSArray *)fs {
  [self createTestDirStructure:fs rootedAt:self.testDir];
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

  [self createTestDirStructure:fs];

  // std::stack<std::string> dirStack;
  WatchItemsPeer watchItems(@"config.plist", NULL);

  std::vector<std::shared_ptr<WatchItemPolicy>> configuredWatchItems1;
  std::vector<std::shared_ptr<WatchItemPolicy>> configuredWatchItems2;

  auto tree1 = std::make_unique<PrefixTree<std::shared_ptr<WatchItemPolicy>>>();
  auto tree2 = std::make_unique<PrefixTree<std::shared_ptr<WatchItemPolicy>>>();

  std::set<WatchItem> paths1;
  std::set<WatchItem> paths2;

  // Add initial set of items as "prefix" types
  configuredWatchItems1.push_back(std::make_shared<WatchItemPolicy>("wi2", "./*", false, true));

  [self pushd:@"a"];
  watchItems.BuildPolicyTree(configuredWatchItems1, *tree1, paths1);
  [self popd];

  printf("First Generate...\n");
  tree1->Print();

  // Re-apply policy as "literal" types
  configuredWatchItems2.push_back(std::make_shared<WatchItemPolicy>("wi2", "./*"));

  [self pushd:@"b"];
  watchItems.BuildPolicyTree(configuredWatchItems2, *tree2, paths2);
  [self popd];

  printf("Second Generate...\n");
  tree2->Print();

  std::set<WatchItem> removed_items;
  std::set_difference(paths1.begin(), paths1.end(), paths2.begin(), paths2.end(),
                      std::inserter(removed_items, removed_items.begin()));

  print(paths1, "paths1: ");
  print(paths2, "paths2: ");
  print(removed_items, "Diff: ");
}

- (void)testReload {
  [self createTestDirStructure:@[
    @{
      @"a" : @[ @"f1", @"f2" ],
    },
    @{
      @"b" : @[ @"f1" ],
    },
  ]];

  NSDictionary *config = @{@"all_files" : @{kWatchItemConfigKeyPath : @"*"}};

  WatchItemsPeer watchItems(@"config.plist", NULL);

  [self pushd:@"a"];
  watchItems.ReloadConfig(config);
  [self popd];

  print(watchItems.currently_monitored_paths_, "Watch paths (initial): ");

  [self pushd:@"b"];
  watchItems.ReloadConfig(config);
  [self popd];

  print(watchItems.currently_monitored_paths_, "Watch paths (reloaded): ");
}

@end
