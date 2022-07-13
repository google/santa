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

#import <XCTest/XCTest.h>

#import "Source/common/SNTRule.h"

@interface SNTRuleTest : XCTestCase
@end

@implementation SNTRuleTest

- (void)testInitWithDictionaryValid {
  SNTRule *sut; 
  
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier": @"some-sort-of-identifier",
    @"policy": @"ALLOWLIST",
    @"rule_type": @"BINARY",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"some-sort-of-identifier");
  XCTAssertEqual(sut.type, SNTRuleTypeBinary);
  XCTAssertEqual(sut.state, SNTRuleStateAllow);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"sha256": @"some-sort-of-identifier",
    @"policy": @"BLOCKLIST",
    @"rule_type": @"CERTIFICATE",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"some-sort-of-identifier");
  XCTAssertEqual(sut.type, SNTRuleTypeCertificate);
  XCTAssertEqual(sut.state, SNTRuleStateBlock);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier": @"some-sort-of-identifier",
    @"policy": @"SILENT_BLOCKLIST",
    @"rule_type": @"TEAMID",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"some-sort-of-identifier");
  XCTAssertEqual(sut.type, SNTRuleTypeTeamID);
  XCTAssertEqual(sut.state, SNTRuleStateSilentBlock);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier": @"some-sort-of-identifier",
    @"policy": @"ALLOWLIST_COMPILER",
    @"rule_type": @"BINARY",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"some-sort-of-identifier");
  XCTAssertEqual(sut.type, SNTRuleTypeBinary);
  XCTAssertEqual(sut.state, SNTRuleStateAllowCompiler);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier": @"some-sort-of-identifier",
    @"policy": @"REMOVE",
    @"rule_type": @"TEAMID",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"some-sort-of-identifier");
  XCTAssertEqual(sut.type, SNTRuleTypeTeamID);
  XCTAssertEqual(sut.state, SNTRuleStateRemove);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier": @"some-sort-of-identifier",
    @"policy": @"ALLOWLIST",
    @"rule_type": @"TEAMID",
    @"custom_msg": @"A custom block message",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"some-sort-of-identifier");
  XCTAssertEqual(sut.type, SNTRuleTypeTeamID);
  XCTAssertEqual(sut.state, SNTRuleStateAllow);
  XCTAssertEqualObjects(sut.customMsg, @"A custom block message");
}

- (void)testInitWithDictionaryInvalid {
  SNTRule *sut; 
  
  sut = [[SNTRule alloc] initWithDictionary:@{ }];
  XCTAssertNil(sut);

  sut = [[SNTRule alloc] initWithDictionary:@{ 
    @"identifier": @"an-identifier",
  }];
  XCTAssertNil(sut);

  sut = [[SNTRule alloc] initWithDictionary:@{ 
    @"identifier": @"an-identifier",
    @"policy": @"OTHERPOLICY",
    @"rule_type": @"BINARY",
  }];
  XCTAssertNil(sut);

  sut = [[SNTRule alloc] initWithDictionary:@{ 
    @"identifier": @"an-identifier",
    @"policy": @"ALLOWLIST",
    @"rule_type": @"OTHER_RULE_TYPE",
  }];
  XCTAssertNil(sut);
}

@end

