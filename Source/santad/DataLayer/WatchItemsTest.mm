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
#include <map>
#include <memory>
#include <vector>

#include "Source/common/PrefixTree.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/DataLayer/WatchItems.h"

using santa::common::PrefixTree;
using santa::santad::data_layer::WatchItemPolicy;
using santa::santad::data_layer::WatchItems;

namespace santa::santad::data_layer {

class WatchItemsPeer : public WatchItems {
 public:
  using WatchItems::ReloadConfig;
  using WatchItems::WatchItems;
};

}  // namespace santa::santad::data_layer

using santa::santad::data_layer::WatchItemsPeer;

static constexpr std::string_view kBadPolicyName("__BAD_NAME__");
static constexpr std::string_view kBadPolicyPath("__BAD_PATH__");
static constexpr std::string_view kVersion("v0.1");

static std::shared_ptr<WatchItemPolicy> MakeBadPolicy() {
  return std::make_shared<WatchItemPolicy>(kBadPolicyName, kBadPolicyPath);
}

static NSMutableDictionary *WrapWatchItemsConfig(NSDictionary *config) {
  return [@{@"Version" : @(kVersion.data()), @"WatchItems" : [config mutableCopy]} mutableCopy];
}

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

- (void)testReloadScenarios {
  [self createTestDirStructure:@[
    @{
      @"a" : @[ @"f1", @"f2" ],
    },
    @{
      @"b" : @[ @"f1" ],
    },
  ]];

  NSDictionary *allFilesPolicy = @{kWatchItemConfigKeyPath : @"*"};
  NSDictionary *configAllFilesOriginal =
    WrapWatchItemsConfig(@{@"all_files_orig" : allFilesPolicy});
  NSDictionary *configAllFilesRename =
    WrapWatchItemsConfig(@{@"all_files_rename" : allFilesPolicy});

  std::optional<std::shared_ptr<WatchItemPolicy>> policy;

  // Changes in config dictionary will update policy info even if the
  // filesystem didn't change.
  {
    WatchItemsPeer watchItems(nil, NULL, NULL);
    [self pushd:@"a"];
    watchItems.ReloadConfig(configAllFilesOriginal);

    policy = watchItems.FindPolicyForPath("f1");
    XCTAssertCStringEqual(policy.value_or(MakeBadPolicy())->name.c_str(), "all_files_orig");

    watchItems.ReloadConfig(configAllFilesRename);
    policy = watchItems.FindPolicyForPath("f1");
    XCTAssertCStringEqual(policy.value_or(MakeBadPolicy())->name.c_str(), "all_files_rename");

    policy = watchItems.FindPolicyForPath("f1");
    XCTAssertCStringEqual(policy.value_or(MakeBadPolicy())->name.c_str(), "all_files_rename");
    [self popd];
  }

  // Changes to fileystem structure are reflected when a config is reloaded
  {
    WatchItemsPeer watchItems(nil, NULL, NULL);
    [self pushd:@"a"];
    watchItems.ReloadConfig(configAllFilesOriginal);
    [self popd];

    policy = watchItems.FindPolicyForPath("f2");
    XCTAssertCStringEqual(policy.value_or(MakeBadPolicy())->name.c_str(), "all_files_orig");

    [self pushd:@"b"];
    watchItems.ReloadConfig(configAllFilesOriginal);
    [self popd];

    policy = watchItems.FindPolicyForPath("f2");
    XCTAssertFalse(policy.has_value());
  }
}

- (void)testPeriodicTask {
  // Ensure watch item policy memory is properly handled
  [self createTestDirStructure:@[ @"f1", @"f2", @"weird1" ]];

  NSDictionary *fFiles = @{
    kWatchItemConfigKeyPath : @"f?",
    kWatchItemConfigKeyIsPrefix : @(NO),
  };
  NSDictionary *weirdFiles = @{
    kWatchItemConfigKeyPath : @"weird?",
    kWatchItemConfigKeyIsPrefix : @(NO),
  };

  NSString *configFile = @"config.plist";
  NSDictionary *firstConfig = WrapWatchItemsConfig(@{@"f_files" : fFiles});
  NSDictionary *secondConfig =
    WrapWatchItemsConfig(@{@"f_files" : fFiles, @"weird_files" : weirdFiles});

  // std::optional<std::shared_ptr<WatchItemPolicy>> policy;

  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);
  (void)timer;

  const uint64 periodicFlushMS = 1000;
  dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 0),
                            NSEC_PER_MSEC * periodicFlushMS, 0);

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  auto watchItems = std::make_shared<WatchItemsPeer>(configFile, self.q, timer, ^{
    dispatch_semaphore_signal(sema);
  });

  // Move into the base test directory and write the config to disk
  [self pushd:@""];
  XCTAssertTrue([firstConfig writeToFile:configFile atomically:YES]);

  // Ensure no policy has been loaded yet
  XCTAssertFalse(watchItems->FindPolicyForPath("f1").has_value());
  XCTAssertFalse(watchItems->FindPolicyForPath("weird1").has_value());

  // Begin the periodic task
  watchItems->BeginPeriodicTask();

  // The first run of the task starts immediately
  // Wait for the first iteration and check for the expected policy
  XCTAssertSemaTrue(sema, 5, "Periodic task did not complete within expected window");
  XCTAssertTrue(watchItems->FindPolicyForPath("f1").has_value());
  XCTAssertFalse(watchItems->FindPolicyForPath("weird1").has_value());

  // Write the config update
  XCTAssertTrue([secondConfig writeToFile:configFile atomically:YES]);

  // Wait for the new config to be loaded and check for the new expected policies
  XCTAssertSemaTrue(sema, 5, "Periodic task did not complete within expected window");
  XCTAssertTrue(watchItems->FindPolicyForPath("f1").has_value());
  XCTAssertTrue(watchItems->FindPolicyForPath("weird1").has_value());

  [self popd];
}

- (void)testPolicyLookup {
  // Test multiple, more comprehensive policies before/after config reload
  [self createTestDirStructure:@[
    @{
      @"foo" : @[ @"bar.txt", @"bar.txt.tmp" ],
      @"baz" : @[ @{@"qaz" : @[]} ],
    },
    @"f1",
  ]];

  NSMutableDictionary *config = WrapWatchItemsConfig(@{
    @"foo_subdir" : @{
      kWatchItemConfigKeyPath : @"./foo",
      kWatchItemConfigKeyIsPrefix : @(YES),
    }
  });

  WatchItemsPeer watchItems(nil, NULL, NULL);

  // Initially nothing should be in the map
  XCTAssertFalse(watchItems.FindPolicyForPath("./foo").has_value());

  // Load the initial config
  [self pushd:@""];
  watchItems.ReloadConfig(config);
  [self popd];

  {
    // Test expected values with the inital policy
    const std::map<std::string_view, std::string_view> pathToPolicyName = {
      {"./foo", "foo_subdir"},
      {"./foo/bar.txt.tmp", "foo_subdir"},
      {"./foo/bar.txt", "foo_subdir"},
      {"./does/not/exist", kBadPolicyName},
    };

    for (const auto &kv : pathToPolicyName) {
      std::optional<std::shared_ptr<WatchItemPolicy>> policy =
        watchItems.FindPolicyForPath(kv.first.data());
      XCTAssertCStringEqual(policy.value_or(MakeBadPolicy())->name.c_str(), kv.second.data());
    }
  }

  // Add a new policy and reload the config
  NSDictionary *barTxtFilePolicy = @{
    kWatchItemConfigKeyPath : @"./foo/bar.txt",
    kWatchItemConfigKeyIsPrefix : @(NO),
  };
  [config[@"WatchItems"] setObject:barTxtFilePolicy forKey:@"bar_txt"];

  // Load the updated config
  [self pushd:@""];
  watchItems.ReloadConfig(config);
  [self popd];

  {
    // Test expected values with the updated policy
    const std::map<std::string_view, std::string_view> pathToPolicyName = {
      {"./foo", "foo_subdir"},
      {"./foo/bar.txt.tmp", "foo_subdir"},
      {"./foo/bar.txt", "bar_txt"},
      {"./does/not/exist", kBadPolicyName},
    };

    for (const auto &kv : pathToPolicyName) {
      std::optional<std::shared_ptr<WatchItemPolicy>> policy =
        watchItems.FindPolicyForPath(kv.first.data());
      XCTAssertCStringEqual(policy.value_or(MakeBadPolicy())->name.c_str(), kv.second.data());
    }
  }

  // Add a catch-all policy that should only affect the previously non-matching path
  NSDictionary *catchAllFilePolicy = @{
    kWatchItemConfigKeyPath : @".",
    kWatchItemConfigKeyIsPrefix : @(YES),
  };
  [config[@"WatchItems"] setObject:catchAllFilePolicy forKey:@"dot_everything"];

  // Load the updated config
  [self pushd:@""];
  watchItems.ReloadConfig(config);
  [self popd];

  {
    // Test expected values with the catch-all policy
    const std::map<std::string_view, std::string_view> pathToPolicyName = {
      {"./foo", "foo_subdir"},
      {"./foo/bar.txt.tmp", "foo_subdir"},
      {"./foo/bar.txt", "bar_txt"},
      {"./does/not/exist", "dot_everything"},
    };

    for (const auto &kv : pathToPolicyName) {
      std::optional<std::shared_ptr<WatchItemPolicy>> policy =
        watchItems.FindPolicyForPath(kv.first.data());
      XCTAssertCStringEqual(policy.value_or(MakeBadPolicy())->name.c_str(), kv.second.data());
    }
  }

  // Now remove the foo_subdir rule, previous matches should fallback to the catch-all
  [config[@"WatchItems"] removeObjectForKey:@"foo_subdir"];
  [self pushd:@""];
  watchItems.ReloadConfig(config);
  [self popd];

  {
    // Test expected values with the foo_subdir policy removed
    const std::map<std::string_view, std::string_view> pathToPolicyName = {
      {"./foo", "dot_everything"},
      {"./foo/bar.txt.tmp", "dot_everything"},
      {"./foo/bar.txt", "bar_txt"},
      {"./does/not/exist", "dot_everything"},
    };

    for (const auto &kv : pathToPolicyName) {
      std::optional<std::shared_ptr<WatchItemPolicy>> policy =
        watchItems.FindPolicyForPath(kv.first.data());
      XCTAssertCStringEqual(policy.value_or(MakeBadPolicy())->name.c_str(), kv.second.data());
    }
  }
}

- (void)testPolicyVersion {
  NSMutableDictionary *config = WrapWatchItemsConfig(@{});

  WatchItemsPeer watchItems(nil, NULL, NULL);
  watchItems.ReloadConfig(config);

  XCTAssertCStringEqual(watchItems.PolicyVersion().c_str(), kVersion.data());
}

@end
