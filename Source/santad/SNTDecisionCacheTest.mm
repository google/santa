/// Copyright 2022 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <dispatch/dispatch.h>
#include <sys/stat.h>
#include "Source/common/SNTCachedDecision.h"

#import "Source/common/SNTCommon.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTRule.h"
#include "Source/common/TestUtils.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTDatabaseController.h"
#import "Source/santad/SNTDecisionCache.h"

SNTCachedDecision *MakeCachedDecision(struct stat sb, SNTEventState decision) {
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];

  cd.decision = decision;
  cd.sha256 = @"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  cd.vnodeId = {
    .fsid = 0,
    .fileid = sb.st_ino,
  };

  return cd;
}

@interface SNTDecisionCacheTest : XCTestCase
@property id mockDatabaseController;
@property id mockRuleDatabase;
@end

@implementation SNTDecisionCacheTest

- (void)setUp {
  self.mockDatabaseController = OCMClassMock([SNTDatabaseController class]);
  self.mockRuleDatabase = OCMStrictClassMock([SNTRuleTable class]);
}

- (void)testBasicOperation {
  SNTDecisionCache *dc = [SNTDecisionCache sharedCache];

  struct stat sb = MakeStat();

  // First make sure the item isn't in the cache
  XCTAssertNil([dc cachedDecisionForFile:sb]);

  // Add the item to the cache
  SNTCachedDecision *cd = MakeCachedDecision(sb, SNTEventStateAllowTeamID);
  [dc cacheDecision:cd];

  // Ensure the item exists in the cache
  SNTCachedDecision *cachedCD = [dc cachedDecisionForFile:sb];
  XCTAssertNotNil(cachedCD);
  XCTAssertEqual(cachedCD.decision, cd.decision);
  XCTAssertEqual(cachedCD.vnodeId.fileid, cd.vnodeId.fileid);

  // Delete the item from the cache and ensure it no longer exists
  [dc forgetCachedDecisionForFile:sb];
  XCTAssertNil([dc cachedDecisionForFile:sb]);
}

- (void)testResetTimestampForCachedDecision {
  SNTDecisionCache *dc = [SNTDecisionCache sharedCache];
  struct stat sb = MakeStat();
  SNTCachedDecision *cd = MakeCachedDecision(sb, SNTEventStateAllowTransitive);

  [dc cacheDecision:cd];

  OCMStub([self.mockDatabaseController ruleTable]).andReturn(self.mockRuleDatabase);

  OCMExpect([self.mockRuleDatabase
    resetTimestampForRule:[OCMArg checkWithBlock:^BOOL(SNTRule *rule) {
      return rule.identifier == cd.sha256 && rule.state == SNTRuleStateAllowTransitive &&
             rule.type == SNTRuleTypeBinary;
    }]]);

  [dc resetTimestampForCachedDecision:sb];

  // Timestamps should not be reset so frequently. Call a second time quickly
  // but do not register a second expectation so that the test will fail if
  // timestamps are actually reset a second time.
  [dc resetTimestampForCachedDecision:sb];

  XCTAssertTrue(OCMVerifyAll(self.mockRuleDatabase));
}

@end
