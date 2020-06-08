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

#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTRule.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"

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
  r.state = SNTRuleStateBlock;
  r.type = SNTRuleTypeBinary;
  r.customMsg = @"A rule";
  return r;
}

- (SNTRule *)_exampleCertRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.shasum = @"b";
  r.state = SNTRuleStateAllow;
  r.type = SNTRuleTypeCertificate;
  return r;
}

- (void)testAddRulesNotClean {
  NSUInteger ruleCount = self.sut.ruleCount;
  NSUInteger binaryRuleCount = self.sut.binaryRuleCount;

  NSError *error;
  [self.sut addRules:@[ [self _exampleBinaryRule] ] cleanSlate:NO error:&error];

  XCTAssertEqual(self.sut.ruleCount, ruleCount + 1);
  XCTAssertEqual(self.sut.binaryRuleCount, binaryRuleCount + 1);
  XCTAssertNil(error);
}

- (void)testAddRulesClean {
  // Add a binary rule without clean slate
  NSError *error = nil;
  XCTAssertTrue([self.sut addRules:@[ [self _exampleBinaryRule] ] cleanSlate:NO error:&error]);
  XCTAssertNil(error);

  // Now add a cert rule with a clean slate, assert that the binary rule was removed
  error = nil;
  XCTAssertTrue(([self.sut addRules:@[ [self _exampleCertRule] ] cleanSlate:YES error:&error]));
  XCTAssertEqual([self.sut binaryRuleCount], 0);
  XCTAssertNil(error);
}

- (void)testAddMultipleRules {
  NSUInteger ruleCount = self.sut.ruleCount;

  NSError *error;
  [self.sut addRules:@[ [self _exampleBinaryRule],
                        [self _exampleCertRule],
                        [self _exampleBinaryRule] ]
          cleanSlate:NO
               error:&error];

  XCTAssertEqual(self.sut.ruleCount, ruleCount + 2);
  XCTAssertNil(error);
}

- (void)testAddRulesEmptyArray {
  NSError *error;
  XCTAssertFalse([self.sut addRules:@[] cleanSlate:YES error:&error]);
  XCTAssertEqual(error.code, SNTRuleTableErrorEmptyRuleArray);
}

- (void)testAddRulesNilArray {
  NSError *error;
  XCTAssertFalse([self.sut addRules:nil cleanSlate:YES error:&error]);
  XCTAssertEqual(error.code, SNTRuleTableErrorEmptyRuleArray);
}

- (void)testAddInvalidRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.shasum = @"a";
  r.type = SNTRuleTypeCertificate;

  NSError *error;
  XCTAssertFalse([self.sut addRules:@[r] cleanSlate:NO error:&error]);
  XCTAssertEqual(error.code, SNTRuleTableErrorInvalidRule);
}

- (void)testFetchBinaryRule {
  [self.sut addRules:@[ [self _exampleBinaryRule], [self _exampleCertRule] ]
          cleanSlate:NO
               error:nil];

  SNTRule *r = [self.sut ruleForBinarySHA256:@"a" certificateSHA256:nil];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.shasum, @"a");
  XCTAssertEqual(r.type, SNTRuleTypeBinary);

  r = [self.sut ruleForBinarySHA256:@"b" certificateSHA256:nil];
  XCTAssertNil(r);
}

- (void)testFetchCertificateRule {
  [self.sut addRules:@[ [self _exampleBinaryRule], [self _exampleCertRule] ]
          cleanSlate:NO
               error:nil];

  SNTRule *r = [self.sut ruleForBinarySHA256:nil certificateSHA256:@"b"];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.shasum, @"b");
  XCTAssertEqual(r.type, SNTRuleTypeCertificate);

  r = [self.sut ruleForBinarySHA256:nil certificateSHA256:@"a"];
  XCTAssertNil(r);
}

- (void)testFetchRuleOrdering {
  [self.sut addRules:@[ [self _exampleCertRule], [self _exampleBinaryRule] ]
          cleanSlate:NO
               error:nil];

  // This test verifies that the implicit rule ordering we've been abusing is still working.
  // See the comment in SNTRuleTable#ruleForBinarySHA256:certificateSHA256:
  SNTRule *r = [self.sut ruleForBinarySHA256:@"a" certificateSHA256:@"b"];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.shasum, @"a");
  XCTAssertEqual(r.type, SNTRuleTypeBinary, @"Implicit rule ordering failed");
}

- (void)testBadDatabase {
  NSString *dbPath = [NSTemporaryDirectory() stringByAppendingString:@"sntruletabletest_baddb.db"];
  [@"some text" writeToFile:dbPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];

  FMDatabaseQueue *dbq = [[FMDatabaseQueue alloc] initWithPath:dbPath];
  SNTRuleTable *sut = [[SNTRuleTable alloc] initWithDatabaseQueue:dbq];

  [sut addRules:@[ [self _exampleBinaryRule] ] cleanSlate:NO error:nil];
  XCTAssertGreaterThan(sut.ruleCount, 0);

  [[NSFileManager defaultManager] removeItemAtPath:dbPath error:NULL];
}

@end
