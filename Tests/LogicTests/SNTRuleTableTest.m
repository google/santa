/// Copyright 2015 Google Inc. All rights reserved.
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

#import "SNTRule.h"
#import "SNTRuleTable.h"

/// This test case actually tests SNTRuleTable and SNTRule
@interface SNTRuleTableTest : XCTestCase
@property SNTRuleTable *sut;
@property FMDatabaseQueue *dbq;
@end

@implementation SNTRuleTableTest

- (void)setUp {
  [super setUp];

  self.dbq = [[FMDatabaseQueue alloc] init];
  self.sut = [[SNTRuleTable alloc] initWithDatabaseQueue:self.dbq];
}

- (SNTRule *)_exampleBinaryRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.shasum = @"a";
  r.state = RULESTATE_BLACKLIST;
  r.type = RULETYPE_BINARY;
  r.customMsg = @"A rule";
  return r;
}

- (SNTRule *)_exampleCertRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.shasum = @"b";
  r.state = RULESTATE_WHITELIST;
  r.type = RULETYPE_CERT;
  return r;
}

- (void)testAddRulesNotClean {
  NSUInteger ruleCount = self.sut.ruleCount;
  NSUInteger binaryRuleCount = self.sut.binaryRuleCount;

  [self.sut addRules:@[ [self _exampleBinaryRule] ] cleanSlate:NO];

  XCTAssertEqual(self.sut.ruleCount, ruleCount + 1);
  XCTAssertEqual(self.sut.binaryRuleCount, binaryRuleCount + 1);
}

- (void)testAddRulesClean {
  // If SNTRuleTable doesn't start with some rules, this test doesn't work properly.
  XCTAssert(self.sut.ruleCount);

  [self.sut addRules:@[ [self _exampleBinaryRule] ] cleanSlate:YES];

  XCTAssertEqual(self.sut.ruleCount, 1);
  XCTAssertEqual(self.sut.binaryRuleCount, 1);
}

- (void)testAddMultipleRules {
  [self.sut addRules:@[ [self _exampleBinaryRule],
                        [self _exampleCertRule],
                        [self _exampleBinaryRule] ]
          cleanSlate:YES];

  XCTAssertEqual(self.sut.ruleCount, 2);
}

- (void)testAddRulesEmptyArray {
  XCTAssertFalse([self.sut addRules:@[] cleanSlate:YES]);
}

- (void)testAddRulesNilArray {
  XCTAssertFalse([self.sut addRules:nil cleanSlate:YES]);
}

- (void)testFetchBinaryRule {
  [self.sut addRules:@[ [self _exampleBinaryRule], [self _exampleCertRule] ] cleanSlate:YES];

  SNTRule *r = [self.sut binaryRuleForSHA256:@"a"];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.shasum, @"a");
  XCTAssertEqual(r.type, RULETYPE_BINARY);

  r = [self.sut binaryRuleForSHA256:@"b"];
  XCTAssertNil(r);
}

- (void)testFetchCertificateRule {
  [self.sut addRules:@[ [self _exampleBinaryRule], [self _exampleCertRule] ] cleanSlate:YES];

  SNTRule *r = [self.sut certificateRuleForSHA256:@"b"];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.shasum, @"b");
  XCTAssertEqual(r.type, RULETYPE_CERT);

  r = [self.sut certificateRuleForSHA256:@"a"];
  XCTAssertNil(r);
}

@end
