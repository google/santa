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

@interface SNTRuleTable (Testing)
@property NSString *santadCertSHA;
@property NSString *launchdCertSHA;
@end

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
  r.state = SNTRuleStateBlacklist;
  r.type = SNTRuleTypeBinary;
  r.customMsg = @"A rule";
  return r;
}

- (SNTRule *)_exampleCertRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.shasum = @"b";
  r.state = SNTRuleStateWhitelist;
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
  // Assert that insert without 'self' and launchd cert hashes fails
  NSError *error;
  XCTAssertFalse([self.sut addRules:@[ [self _exampleBinaryRule] ] cleanSlate:YES error:&error]);
  XCTAssertEqual(error.code, SNTRuleTableErrorMissingRequiredRule);

  // Now add a binary rule without clean slate
  error = nil;
  XCTAssertTrue([self.sut addRules:@[ [self _exampleBinaryRule] ] cleanSlate:NO error:&error]);
  XCTAssertNil(error);

  // Now add a cert rule + the required rules as a clean slate,
  // assert that the binary rule was removed
  SNTRule *r1 = [[SNTRule alloc] init];
  r1.shasum = self.sut.launchdCertSHA;
  r1.state = SNTRuleStateWhitelist;
  r1.type = SNTRuleTypeCertificate;
  SNTRule *r2 = [[SNTRule alloc] init];
  r2.shasum = self.sut.santadCertSHA;
  r2.state = SNTRuleStateWhitelist;
  r2.type = SNTRuleTypeCertificate;

  error = nil;
  XCTAssertTrue(([self.sut addRules:@[ [self _exampleCertRule], r1, r2 ]
                         cleanSlate:YES
                              error:&error]));
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
