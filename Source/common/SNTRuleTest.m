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
#include "Source/common/SNTCommonEnums.h"

#import "Source/common/SNTRule.h"

@interface SNTRuleTest : XCTestCase
@end

@implementation SNTRuleTest

- (void)testInitWithDictionaryValid {
  SNTRule *sut;

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"BINARY",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier,
                        @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  XCTAssertEqual(sut.type, SNTRuleTypeBinary);
  XCTAssertEqual(sut.state, SNTRuleStateAllow);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"sha256" : @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
    @"policy" : @"BLOCKLIST",
    @"rule_type" : @"CERTIFICATE",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier,
                        @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  XCTAssertEqual(sut.type, SNTRuleTypeCertificate);
  XCTAssertEqual(sut.state, SNTRuleStateBlock);

  // Ensure a Binary and Certificate rules properly convert identifiers to lowercase.
  for (NSString *ruleType in @[ @"BINARY", @"CERTIFICATE" ]) {
    sut = [[SNTRule alloc] initWithDictionary:@{
      @"identifier" : @"B7C1E3FD640C5F211C89B02C2C6122F78CE322AA5C56EB0BB54BC422A8F8B670",
      @"policy" : @"BLOCKLIST",
      @"rule_type" : ruleType,
    }];
    XCTAssertNotNil(sut);
    XCTAssertEqualObjects(sut.identifier,
                          @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  }

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"ABCDEFGHIJ",
    @"policy" : @"SILENT_BLOCKLIST",
    @"rule_type" : @"TEAMID",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"ABCDEFGHIJ");
  XCTAssertEqual(sut.type, SNTRuleTypeTeamID);
  XCTAssertEqual(sut.state, SNTRuleStateSilentBlock);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
    @"policy" : @"ALLOWLIST_COMPILER",
    @"rule_type" : @"BINARY",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier,
                        @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  XCTAssertEqual(sut.type, SNTRuleTypeBinary);
  XCTAssertEqual(sut.state, SNTRuleStateAllowCompiler);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"ABCDEFGHIJ",
    @"policy" : @"REMOVE",
    @"rule_type" : @"TEAMID",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"ABCDEFGHIJ");
  XCTAssertEqual(sut.type, SNTRuleTypeTeamID);
  XCTAssertEqual(sut.state, SNTRuleStateRemove);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"ABCDEFGHIJ",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"TEAMID",
    @"custom_msg" : @"A custom block message",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"ABCDEFGHIJ");
  XCTAssertEqual(sut.type, SNTRuleTypeTeamID);
  XCTAssertEqual(sut.state, SNTRuleStateAllow);
  XCTAssertEqualObjects(sut.customMsg, @"A custom block message");

  // TeamIDs must be 10 chars in length
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"A",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"TEAMID",
  }];
  XCTAssertNil(sut);

  // TeamIDs must be only alphanumeric chars
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"ßßßßßßßßßß",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"TEAMID",
  }];
  XCTAssertNil(sut);

  // TeamIDs are converted to uppercase
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"abcdefghij",
    @"policy" : @"REMOVE",
    @"rule_type" : @"TEAMID",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"ABCDEFGHIJ");

  // SigningID tests
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"ABCDEFGHIJ:com.example",
    @"policy" : @"REMOVE",
    @"rule_type" : @"SIGNINGID",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"ABCDEFGHIJ:com.example");
  XCTAssertEqual(sut.type, SNTRuleTypeSigningID);
  XCTAssertEqual(sut.state, SNTRuleStateRemove);

  // Invalid SingingID tests:
  for (NSString *ident in @[
         @":com.example",     // missing team ID
         @"ABCDEFGHIJ:",      // missing signing ID
         @"ABC:com.example",  // Invalid team id
         @":",                // missing team and signing IDs
         @"",                 // empty string
       ]) {
    sut = [[SNTRule alloc] initWithDictionary:@{
      @"identifier" : ident,
      @"policy" : @"REMOVE",
      @"rule_type" : @"SIGNINGID",
    }];
    XCTAssertNil(sut);
  }

  // Signing ID with lower team ID has case fixed up
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"abcdefghij:com.example",
    @"policy" : @"REMOVE",
    @"rule_type" : @"SIGNINGID",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"ABCDEFGHIJ:com.example");

  // Signing ID with lower platform team ID is left alone
  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"platform:com.example",
    @"policy" : @"REMOVE",
    @"rule_type" : @"SIGNINGID",
  }];
  XCTAssertNotNil(sut);
  XCTAssertEqualObjects(sut.identifier, @"platform:com.example");
}

- (void)testInitWithDictionaryInvalid {
  SNTRule *sut;

  sut = [[SNTRule alloc] initWithDictionary:@{}];
  XCTAssertNil(sut);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
  }];
  XCTAssertNil(sut);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"an-identifier",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"BINARY",
  }];
  XCTAssertNil(sut);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
    @"policy" : @"OTHERPOLICY",
    @"rule_type" : @"BINARY",
  }];
  XCTAssertNil(sut);

  sut = [[SNTRule alloc] initWithDictionary:@{
    @"identifier" : @"an-identifier",
    @"policy" : @"ALLOWLIST",
    @"rule_type" : @"OTHER_RULE_TYPE",
  }];
  XCTAssertNil(sut);
}

@end
