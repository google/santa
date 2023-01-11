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

#include <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
#import <XCTest/XCTest.h>
#include <dispatch/dispatch.h>
#include <sys/syslimits.h>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <map>
#include <memory>
#include <variant>
#include <vector>

#include "Source/common/TestUtils.h"
#import "Source/common/Unit.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/DataLayer/WatchItems.h"

using santa::common::Unit;
using santa::santad::data_layer::kWatchItemPolicyDefaultAllowReadAccess;
using santa::santad::data_layer::kWatchItemPolicyDefaultAuditOnly;
using santa::santad::data_layer::kWatchItemPolicyDefaultPathType;
using santa::santad::data_layer::WatchItemPathType;
using santa::santad::data_layer::WatchItemPolicy;
using santa::santad::data_layer::WatchItems;

using PathAndTypePair = std::pair<std::string, WatchItemPathType>;
using PathList = std::vector<PathAndTypePair>;
using ProcessList = std::vector<WatchItemPolicy::Process>;

namespace santa::santad::data_layer {

extern bool ParseConfig(NSDictionary *config,
                        std::vector<std::shared_ptr<WatchItemPolicy>> &policies, NSError **err);
extern bool ParseConfigSingleWatchItem(NSString *name, NSDictionary *watch_item,
                                       std::vector<std::shared_ptr<WatchItemPolicy>> &policies,
                                       NSError **err);
extern std::variant<Unit, PathList> VerifyConfigWatchItemPaths(NSArray<id> *paths, NSError **err);
extern std::variant<Unit, ProcessList> VerifyConfigWatchItemProcesses(NSDictionary *watch_item,
                                                                      NSError **err);
class WatchItemsPeer : public WatchItems {
 public:
  using WatchItems::ReloadConfig;
  using WatchItems::WatchItems;
};

}  // namespace santa::santad::data_layer

using santa::santad::data_layer::ParseConfig;
using santa::santad::data_layer::ParseConfigSingleWatchItem;
using santa::santad::data_layer::VerifyConfigWatchItemPaths;
using santa::santad::data_layer::VerifyConfigWatchItemProcesses;
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

static NSString *RepeatedString(NSString *str, NSUInteger len) {
  return [@"" stringByPaddingToLength:len withString:str startingAtIndex:0];
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

  NSDictionary *allFilesPolicy = @{kWatchItemConfigKeyPaths : @[ @"*" ]};
  NSDictionary *configAllFilesOriginal =
    WrapWatchItemsConfig(@{@"all_files_orig" : allFilesPolicy});
  NSDictionary *configAllFilesRename =
    WrapWatchItemsConfig(@{@"all_files_rename" : allFilesPolicy});

  WatchItems::VersionAndPolicies policies;

  std::vector<std::string_view> f1Path = {"f1"};
  std::vector<std::string_view> f2Path = {"f2"};

  // Changes in config dictionary will update policy info even if the
  // filesystem didn't change.
  {
    WatchItemsPeer watchItems(nil, NULL, NULL);
    [self pushd:@"a"];
    watchItems.ReloadConfig(configAllFilesOriginal);

    policies = watchItems.FindPolciesForPaths(f1Path);
    XCTAssertCStringEqual(policies.second[0].value_or(MakeBadPolicy())->name.c_str(),
                          "all_files_orig");

    watchItems.ReloadConfig(configAllFilesRename);
    policies = watchItems.FindPolciesForPaths(f1Path);
    XCTAssertCStringEqual(policies.second[0].value_or(MakeBadPolicy())->name.c_str(),
                          "all_files_rename");

    policies = watchItems.FindPolciesForPaths(f1Path);
    XCTAssertCStringEqual(policies.second[0].value_or(MakeBadPolicy())->name.c_str(),
                          "all_files_rename");
    [self popd];
  }

  // Changes to fileystem structure are reflected when a config is reloaded
  {
    WatchItemsPeer watchItems(nil, NULL, NULL);
    [self pushd:@"a"];
    watchItems.ReloadConfig(configAllFilesOriginal);
    [self popd];

    policies = watchItems.FindPolciesForPaths(f2Path);
    XCTAssertCStringEqual(policies.second[0].value_or(MakeBadPolicy())->name.c_str(),
                          "all_files_orig");

    [self pushd:@"b"];
    watchItems.ReloadConfig(configAllFilesOriginal);
    [self popd];

    policies = watchItems.FindPolciesForPaths(f2Path);
    XCTAssertFalse(policies.second[0].has_value());
  }
}

- (void)testPeriodicTask {
  // Ensure watch item policy memory is properly handled
  [self createTestDirStructure:@[ @"f1", @"f2", @"weird1" ]];

  NSDictionary *fFiles = @{
    kWatchItemConfigKeyPaths : @[ @{
      kWatchItemConfigKeyPathsPath : @"f?",
      kWatchItemConfigKeyPathsIsPrefix : @(NO),
    } ]
  };
  NSDictionary *weirdFiles = @{
    kWatchItemConfigKeyPaths : @[ @{
      kWatchItemConfigKeyPathsPath : @"weird?",
      kWatchItemConfigKeyPathsIsPrefix : @(NO),
    } ]
  };

  NSString *configFile = @"config.plist";
  NSDictionary *firstConfig = WrapWatchItemsConfig(@{@"f_files" : fFiles});
  NSDictionary *secondConfig =
    WrapWatchItemsConfig(@{@"f_files" : fFiles, @"weird_files" : weirdFiles});

  dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.q);

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

  std::vector<std::string_view> f1Path = {"f1"};
  std::vector<std::string_view> weird1Path = {"weird1"};

  // Ensure no policy has been loaded yet
  XCTAssertFalse(watchItems->FindPolciesForPaths(f1Path).second[0].has_value());
  XCTAssertFalse(watchItems->FindPolciesForPaths(weird1Path).second[0].has_value());

  // Begin the periodic task
  watchItems->BeginPeriodicTask();

  // The first run of the task starts immediately
  // Wait for the first iteration and check for the expected policy
  XCTAssertSemaTrue(sema, 5, "Periodic task did not complete within expected window");
  XCTAssertTrue(watchItems->FindPolciesForPaths(f1Path).second[0].has_value());
  XCTAssertFalse(watchItems->FindPolciesForPaths(weird1Path).second[0].has_value());

  // Write the config update
  XCTAssertTrue([secondConfig writeToFile:configFile atomically:YES]);

  // Wait for the new config to be loaded and check for the new expected policies
  XCTAssertSemaTrue(sema, 5, "Periodic task did not complete within expected window");
  XCTAssertTrue(watchItems->FindPolciesForPaths(f1Path).second[0].has_value());
  XCTAssertTrue(watchItems->FindPolciesForPaths(weird1Path).second[0].has_value());

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
      kWatchItemConfigKeyPaths : @[ @{
        kWatchItemConfigKeyPathsPath : @"./foo",
        kWatchItemConfigKeyPathsIsPrefix : @(YES),
      } ]
    }
  });

  WatchItemsPeer watchItems(nil, NULL, NULL);
  WatchItems::VersionAndPolicies policies;

  // Resultant vector is same size as input vector
  // Initially nothing should be in the map
  std::vector<std::string_view> paths = {};
  XCTAssertEqual(watchItems.FindPolciesForPaths(paths).second.size(), 0);
  paths.push_back("./foo");
  XCTAssertEqual(watchItems.FindPolciesForPaths(paths).second.size(), 1);
  XCTAssertFalse(watchItems.FindPolciesForPaths(paths).second[0].has_value());
  paths.push_back("./baz");
  XCTAssertEqual(watchItems.FindPolciesForPaths(paths).second.size(), 2);

  // Load the initial config
  [self pushd:@""];
  watchItems.ReloadConfig(config);
  [self popd];

  {
    // Test expected values with the inital policy
    const std::map<std::vector<std::string_view>, std::string_view> pathToPolicyName = {
      {{"./foo"}, "foo_subdir"},
      {{"./foo/bar.txt.tmp"}, "foo_subdir"},
      {{"./foo/bar.txt"}, "foo_subdir"},
      {{"./does/not/exist"}, kBadPolicyName},
    };

    for (const auto &kv : pathToPolicyName) {
      policies = watchItems.FindPolciesForPaths(kv.first);
      XCTAssertCStringEqual(policies.first.data(), kVersion.data());
      XCTAssertCStringEqual(policies.second[0].value_or(MakeBadPolicy())->name.c_str(),
                            kv.second.data());
    }

    // Test multiple lookup
    policies = watchItems.FindPolciesForPaths({"./foo", "./does/not/exist"});
    XCTAssertCStringEqual(policies.second[0].value_or(MakeBadPolicy())->name.c_str(), "foo_subdir");
    XCTAssertFalse(policies.second[1].has_value());
  }

  // Add a new policy and reload the config
  NSDictionary *barTxtFilePolicy = @{
    kWatchItemConfigKeyPaths : @[ @{
      kWatchItemConfigKeyPathsPath : @"./foo/bar.txt",
      kWatchItemConfigKeyPathsIsPrefix : @(NO),
    } ]
  };
  [config[@"WatchItems"] setObject:barTxtFilePolicy forKey:@"bar_txt"];

  // Load the updated config
  [self pushd:@""];
  watchItems.ReloadConfig(config);
  [self popd];

  {
    // Test expected values with the updated policy
    const std::map<std::vector<std::string_view>, std::string_view> pathToPolicyName = {
      {{"./foo"}, "foo_subdir"},
      {{"./foo/bar.txt.tmp"}, "foo_subdir"},
      {{"./foo/bar.txt"}, "bar_txt"},
      {{"./does/not/exist"}, kBadPolicyName},
    };

    for (const auto &kv : pathToPolicyName) {
      policies = watchItems.FindPolciesForPaths(kv.first);
      XCTAssertCStringEqual(policies.second[0].value_or(MakeBadPolicy())->name.c_str(),
                            kv.second.data());
    }
  }

  // Add a catch-all policy that should only affect the previously non-matching path
  NSDictionary *catchAllFilePolicy = @{
    kWatchItemConfigKeyPaths : @[ @{
      kWatchItemConfigKeyPathsPath : @".",
      kWatchItemConfigKeyPathsIsPrefix : @(YES),
    } ]
  };
  [config[@"WatchItems"] setObject:catchAllFilePolicy forKey:@"dot_everything"];

  // Load the updated config
  [self pushd:@""];
  watchItems.ReloadConfig(config);
  [self popd];

  {
    // Test expected values with the catch-all policy
    const std::map<std::vector<std::string_view>, std::string_view> pathToPolicyName = {
      {{"./foo"}, "foo_subdir"},
      {{"./foo/bar.txt.tmp"}, "foo_subdir"},
      {{"./foo/bar.txt"}, "bar_txt"},
      {{"./does/not/exist"}, "dot_everything"},
    };

    for (const auto &kv : pathToPolicyName) {
      policies = watchItems.FindPolciesForPaths(kv.first);
      XCTAssertCStringEqual(policies.second[0].value_or(MakeBadPolicy())->name.c_str(),
                            kv.second.data());
    }
  }

  // Now remove the foo_subdir rule, previous matches should fallback to the catch-all
  [config[@"WatchItems"] removeObjectForKey:@"foo_subdir"];
  [self pushd:@""];
  watchItems.ReloadConfig(config);
  [self popd];

  {
    // Test expected values with the foo_subdir policy removed
    const std::map<std::vector<std::string_view>, std::string_view> pathToPolicyName = {
      {{"./foo"}, "dot_everything"},
      {{"./foo/bar.txt.tmp"}, "dot_everything"},
      {{"./foo/bar.txt"}, "bar_txt"},
      {{"./does/not/exist"}, "dot_everything"},
    };

    for (const auto &kv : pathToPolicyName) {
      policies = watchItems.FindPolciesForPaths(kv.first);
      XCTAssertCStringEqual(policies.second[0].value_or(MakeBadPolicy())->name.c_str(),
                            kv.second.data());
    }
  }
}

- (void)testVerifyConfigWatchItemPaths {
  std::variant<Unit, PathList> path_list;
  NSError *err;

  // Test no paths specified
  path_list = VerifyConfigWatchItemPaths(@[], &err);
  XCTAssertTrue(std::holds_alternative<Unit>(path_list));

  // Test invalid types in paths array
  path_list = VerifyConfigWatchItemPaths(@[ @(0) ], &err);
  XCTAssertTrue(std::holds_alternative<Unit>(path_list));

  // Test path array with long string
  path_list = VerifyConfigWatchItemPaths(@[ RepeatedString(@"A", PATH_MAX + 1) ], &err);
  XCTAssertTrue(std::holds_alternative<Unit>(path_list));

  // Test path array dictionary with missing required key
  path_list = VerifyConfigWatchItemPaths(@[ @{@"FakePath" : @"A"} ], &err);
  XCTAssertTrue(std::holds_alternative<Unit>(path_list));

  // Test path array dictionary with long string
  path_list = VerifyConfigWatchItemPaths(
    @[ @{kWatchItemConfigKeyPathsPath : RepeatedString(@"A", PATH_MAX + 1)} ], &err);
  XCTAssertTrue(std::holds_alternative<Unit>(path_list));

  // Test path array dictionary with default path type
  path_list = VerifyConfigWatchItemPaths(@[ @{kWatchItemConfigKeyPathsPath : @"A"} ], &err);
  XCTAssertTrue(std::holds_alternative<PathList>(path_list));
  XCTAssertEqual(std::get<PathList>(path_list).size(), 1);
  XCTAssertCStringEqual(std::get<PathList>(path_list)[0].first.c_str(), "A");
  XCTAssertEqual(std::get<PathList>(path_list)[0].second, kWatchItemPolicyDefaultPathType);

  // Test path array dictionary with custom path type
  path_list = VerifyConfigWatchItemPaths(
    @[ @{kWatchItemConfigKeyPathsPath : @"A", kWatchItemConfigKeyPathsIsPrefix : @(YES)} ], &err);
  XCTAssertTrue(std::holds_alternative<PathList>(path_list));
  XCTAssertEqual(std::get<PathList>(path_list).size(), 1);
  XCTAssertCStringEqual(std::get<PathList>(path_list)[0].first.c_str(), "A");
  XCTAssertEqual(std::get<PathList>(path_list)[0].second, WatchItemPathType::kPrefix);
}

- (void)testVerifyConfigWatchItemProcesses {
  std::variant<Unit, ProcessList> proc_list;
  NSError *err;

  // Non-existent process list parses successfully, but has no items
  proc_list = VerifyConfigWatchItemProcesses(@{}, &err);
  XCTAssertTrue(std::holds_alternative<ProcessList>(proc_list));
  XCTAssertEqual(std::get<ProcessList>(proc_list).size(), 0);

  // Process list fails to parse if contains non-array type
  proc_list = VerifyConfigWatchItemProcesses(@{kWatchItemConfigKeyProcesses : @""}, &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));
  proc_list = VerifyConfigWatchItemProcesses(@{kWatchItemConfigKeyProcesses : @(0)}, &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));
  proc_list = VerifyConfigWatchItemProcesses(@{kWatchItemConfigKeyProcesses : @{}}, &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));
  proc_list = VerifyConfigWatchItemProcesses(@{kWatchItemConfigKeyProcesses : @[]}, &err);
  XCTAssertTrue(std::holds_alternative<ProcessList>(proc_list));

  // Test a process dictionary with no valid attributes set
  proc_list = VerifyConfigWatchItemProcesses(@{kWatchItemConfigKeyProcesses : @[ @{} ]}, &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test BinaryPath length limits
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
      @[ @{kWatchItemConfigKeyProcessesBinaryPath : RepeatedString(@"A", PATH_MAX + 1)} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test valid BinaryPath
  proc_list = VerifyConfigWatchItemProcesses(
    @{kWatchItemConfigKeyProcesses : @[ @{kWatchItemConfigKeyProcessesBinaryPath : @"mypath"} ]},
    &err);
  XCTAssertTrue(std::holds_alternative<ProcessList>(proc_list));
  XCTAssertEqual(std::get<ProcessList>(proc_list).size(), 1);
  XCTAssertEqual(std::get<ProcessList>(proc_list)[0],
                 WatchItemPolicy::Process("mypath", "", "", {}, ""));

  // Test SigningID length limits
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
      @[ @{kWatchItemConfigKeyProcessesSigningID : RepeatedString(@"A", 513)} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test valid SigningID
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
      @[ @{kWatchItemConfigKeyProcessesSigningID : @"com.google.test"} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<ProcessList>(proc_list));
  XCTAssertEqual(std::get<ProcessList>(proc_list).size(), 1);
  XCTAssertEqual(std::get<ProcessList>(proc_list)[0],
                 WatchItemPolicy::Process("", "com.google.test", "", {}, ""));

  // Test TeamID length limits
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
      @[ @{kWatchItemConfigKeyProcessesTeamID : @"LongerThanExpectedTeamID"} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test valid TeamID
  proc_list = VerifyConfigWatchItemProcesses(
    @{kWatchItemConfigKeyProcesses : @[ @{kWatchItemConfigKeyProcessesTeamID : @"myvalidtid"} ]},
    &err);
  XCTAssertTrue(std::holds_alternative<ProcessList>(proc_list));
  XCTAssertEqual(std::get<ProcessList>(proc_list).size(), 1);
  XCTAssertEqual(std::get<ProcessList>(proc_list)[0],
                 WatchItemPolicy::Process("", "", "myvalidtid", {}, ""));

  // Test CDHash length limits
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
      @[ @{kWatchItemConfigKeyProcessesCDHash : RepeatedString(@"A", CS_CDHASH_LEN * 2 + 1)} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test CDHash hex-only
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
      @[ @{kWatchItemConfigKeyProcessesCDHash : RepeatedString(@"Z", CS_CDHASH_LEN * 2)} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test valid CDHash
  NSString *cdhash = RepeatedString(@"A", CS_CDHASH_LEN * 2);
  std::vector<uint8_t> cdhashBytes(cdhash.length / 2);
  std::fill(cdhashBytes.begin(), cdhashBytes.end(), 0xAA);
  proc_list = VerifyConfigWatchItemProcesses(
    @{kWatchItemConfigKeyProcesses : @[ @{kWatchItemConfigKeyProcessesCDHash : cdhash} ]}, &err);
  XCTAssertTrue(std::holds_alternative<ProcessList>(proc_list));
  XCTAssertEqual(std::get<ProcessList>(proc_list).size(), 1);
  XCTAssertEqual(std::get<ProcessList>(proc_list)[0],
                 WatchItemPolicy::Process("", "", "", cdhashBytes, ""));

  // Test Cert Hash length limits
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[ @{
      kWatchItemConfigKeyProcessesCertificateSha256 :
        RepeatedString(@"A", CC_SHA256_DIGEST_LENGTH * 2 + 1)
    } ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test Cert Hash hex-only
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[ @{
      kWatchItemConfigKeyProcessesCertificateSha256 :
        RepeatedString(@"Z", CC_SHA256_DIGEST_LENGTH * 2)
    } ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test valid Cert Hash
  NSString *certHash = RepeatedString(@"A", CC_SHA256_DIGEST_LENGTH * 2);
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[ @{kWatchItemConfigKeyProcessesCertificateSha256 : certHash} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<ProcessList>(proc_list));
  XCTAssertEqual(std::get<ProcessList>(proc_list).size(), 1);
  XCTAssertEqual(std::get<ProcessList>(proc_list)[0],
                 WatchItemPolicy::Process("", "", "", {}, [certHash UTF8String]));

  // Test valid multiple attributes, multiple procs
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[
      @{
        kWatchItemConfigKeyProcessesBinaryPath : @"mypath1",
        kWatchItemConfigKeyProcessesSigningID : @"com.google.test1",
        kWatchItemConfigKeyProcessesTeamID : @"validtid_1",
        kWatchItemConfigKeyProcessesCDHash : cdhash,
        kWatchItemConfigKeyProcessesCertificateSha256 : certHash,
      },
      @{
        kWatchItemConfigKeyProcessesBinaryPath : @"mypath2",
        kWatchItemConfigKeyProcessesSigningID : @"com.google.test2",
        kWatchItemConfigKeyProcessesTeamID : @"validtid_2",
        kWatchItemConfigKeyProcessesCDHash : cdhash,
        kWatchItemConfigKeyProcessesCertificateSha256 : certHash,
      },
    ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<ProcessList>(proc_list));
  XCTAssertEqual(std::get<ProcessList>(proc_list).size(), 2);
  XCTAssertEqual(std::get<ProcessList>(proc_list)[0],
                 WatchItemPolicy::Process("mypath1", "com.google.test1", "validtid_1", cdhashBytes,
                                          [certHash UTF8String]));
  XCTAssertEqual(std::get<ProcessList>(proc_list)[1],
                 WatchItemPolicy::Process("mypath2", "com.google.test2", "validtid_2", cdhashBytes,
                                          [certHash UTF8String]));
}

- (void)testParseConfig {
  NSError *err;
  std::vector<std::shared_ptr<WatchItemPolicy>> policies;

  // Ensure top level keys must exist and be correct types
  XCTAssertFalse(ParseConfig(@{}, policies, &err));
  XCTAssertFalse(ParseConfig(@{kWatchItemConfigKeyVersion : @(0)}, policies, &err));
  XCTAssertFalse(ParseConfig(@{kWatchItemConfigKeyVersion : @{}}, policies, &err));
  XCTAssertFalse(ParseConfig(@{kWatchItemConfigKeyVersion : @[]}, policies, &err));
  XCTAssertFalse(ParseConfig(@{kWatchItemConfigKeyVersion : @""}, policies, &err));
  XCTAssertFalse(ParseConfig(
    @{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @""}, policies, &err));
  XCTAssertFalse(ParseConfig(
    @{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @[]}, policies, &err));
  XCTAssertFalse(ParseConfig(
    @{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @(0)}, policies, &err));

  // Minimally successful configs without watch items
  XCTAssertTrue(ParseConfig(@{kWatchItemConfigKeyVersion : @"1"}, policies, &err));
  XCTAssertTrue(ParseConfig(
    @{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @{}}, policies, &err));

  // Ensure constraints on watch items entries match expectations
  XCTAssertFalse(ParseConfig(
    @{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @{@(0) : @(0)}}, policies,
    &err));
  XCTAssertFalse(
    ParseConfig(@{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @{@"" : @{}}},
                policies, &err));
  XCTAssertFalse(
    ParseConfig(@{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @{@"1" : @[]}},
                policies, &err));
  XCTAssertFalse(
    ParseConfig(@{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @{@"1" : @{}}},
                policies, &err));

  // Minimally successful config with watch item
  XCTAssertTrue(ParseConfig(@{
    kWatchItemConfigKeyVersion : @"1",
    kWatchItemConfigKeyWatchItems : @{@"1" : @{kWatchItemConfigKeyPaths : @[ @"asdf" ]}}
  },
                            policies, &err));
}

- (void)testParseConfigSingleWatchItem {
  std::vector<std::shared_ptr<WatchItemPolicy>> policies;
  NSError *err;

  // There must be valid Paths in a watch item
  XCTAssertFalse(ParseConfigSingleWatchItem(@"", @{}, policies, &err));
  XCTAssertFalse(
    ParseConfigSingleWatchItem(@"", @{kWatchItemConfigKeyPaths : @[ @"" ]}, policies, &err));
  XCTAssertTrue(
    ParseConfigSingleWatchItem(@"", @{kWatchItemConfigKeyPaths : @[ @"a" ]}, policies, &err));

  // Empty options are fine
  XCTAssertTrue(ParseConfigSingleWatchItem(
    @"", @{kWatchItemConfigKeyPaths : @[ @"a" ], kWatchItemConfigKeyOptions : @{}}, policies,
    &err));

  // If an Options key exist, it must be a dictionary type
  XCTAssertFalse(ParseConfigSingleWatchItem(
    @"", @{kWatchItemConfigKeyPaths : @[ @"a" ], kWatchItemConfigKeyOptions : @[]}, policies,
    &err));
  XCTAssertFalse(ParseConfigSingleWatchItem(
    @"", @{kWatchItemConfigKeyPaths : @[ @"a" ], kWatchItemConfigKeyOptions : @""}, policies,
    &err));
  XCTAssertFalse(ParseConfigSingleWatchItem(
    @"", @{kWatchItemConfigKeyPaths : @[ @"a" ], kWatchItemConfigKeyOptions : @(0)}, policies,
    &err));

  // Options keys must be valid types
  XCTAssertFalse(ParseConfigSingleWatchItem(@"", @{
    kWatchItemConfigKeyPaths : @[ @"a" ],
    kWatchItemConfigKeyOptions : @{kWatchItemConfigKeyOptionsAllowReadAccess : @""}
  },
                                            policies, &err));
  XCTAssertTrue(ParseConfigSingleWatchItem(@"", @{
    kWatchItemConfigKeyPaths : @[ @"a" ],
    kWatchItemConfigKeyOptions : @{kWatchItemConfigKeyOptionsAllowReadAccess : @(0)}
  },
                                           policies, &err));
  XCTAssertFalse(ParseConfigSingleWatchItem(@"", @{
    kWatchItemConfigKeyPaths : @[ @"a" ],
    kWatchItemConfigKeyOptions : @{kWatchItemConfigKeyOptionsAuditOnly : @""}
  },
                                            policies, &err));
  XCTAssertTrue(ParseConfigSingleWatchItem(@"", @{
    kWatchItemConfigKeyPaths : @[ @"a" ],
    kWatchItemConfigKeyOptions : @{kWatchItemConfigKeyOptionsAuditOnly : @(0)}
  },
                                           policies, &err));

  // If processes are specified, they must be valid format
  // Note: Full tests in `testVerifyConfigWatchItemProcesses`
  XCTAssertFalse(ParseConfigSingleWatchItem(
    @"", @{kWatchItemConfigKeyPaths : @[ @"a" ], kWatchItemConfigKeyProcesses : @""}, policies,
    &err));

  // Test the policy vector is populated as expected

  // Test default options with no processes
  policies.clear();
  XCTAssertTrue(
    ParseConfigSingleWatchItem(@"rule", @{kWatchItemConfigKeyPaths : @[ @"a" ]}, policies, &err));
  XCTAssertEqual(policies.size(), 1);
  XCTAssertEqual(*policies[0].get(), WatchItemPolicy("rule", "a", kWatchItemPolicyDefaultPathType,
                                                     kWatchItemPolicyDefaultAllowReadAccess,
                                                     kWatchItemPolicyDefaultAuditOnly, {}));

  // Test multiple paths, options, and processes
  policies.clear();
  std::vector<WatchItemPolicy::Process> procs = {
    WatchItemPolicy::Process("pa", "", "", {}, ""),
    WatchItemPolicy::Process("pb", "", "", {}, ""),
  };

  XCTAssertTrue(ParseConfigSingleWatchItem(@"rule", @{
    kWatchItemConfigKeyPaths :
      @[ @"a", @{kWatchItemConfigKeyPathsPath : @"b", kWatchItemConfigKeyPathsIsPrefix : @(YES)} ],
    kWatchItemConfigKeyOptions : @{
      kWatchItemConfigKeyOptionsAllowReadAccess : @(YES),
      kWatchItemConfigKeyOptionsAuditOnly : @(NO)
    },
    kWatchItemConfigKeyProcesses : @[
      @{kWatchItemConfigKeyProcessesBinaryPath : @"pa"},
      @{kWatchItemConfigKeyProcessesBinaryPath : @"pb"}
    ]
  },
                                           policies, &err));
  XCTAssertEqual(policies.size(), 2);
  XCTAssertEqual(*policies[0].get(),
                 WatchItemPolicy("rule", "a", kWatchItemPolicyDefaultPathType, true, false, procs));
  XCTAssertEqual(*policies[1].get(),
                 WatchItemPolicy("rule", "b", WatchItemPathType::kPrefix, true, false, procs));
}

- (void)testPolicyVersion {
  NSMutableDictionary *config = WrapWatchItemsConfig(@{});

  WatchItemsPeer watchItems(nil, NULL, NULL);
  watchItems.ReloadConfig(config);

  XCTAssertCStringEqual(watchItems.PolicyVersion().c_str(), kVersion.data());
}

@end
