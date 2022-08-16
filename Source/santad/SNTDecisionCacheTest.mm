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

#include <dispatch/dispatch.h>
#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/santad/SNTDecisionCache.h"

@interface SNTDecisionCacheTest : XCTestCase
@property id mockRuleDatabase;
@end

@implementation SNTDecisionCacheTest

- (void)setUp {
  // self.mockRuleDatabase = OCMClassMock([SNTRuleTable class]);
}

- (void)testBasicOperation {
  // SNTDecisionCache *dc = [SNTDecisionCache sharedCache];
}

@end
